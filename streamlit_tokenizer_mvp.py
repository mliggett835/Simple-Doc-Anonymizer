import streamlit as st
import re
import json
import uuid
from datetime import datetime
import pandas as pd

# Simple session state setup
if 'session_id' not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())[:8]
if 'token_mappings' not in st.session_state:
    st.session_state.token_mappings = {}
if 'anonymized_content' not in st.session_state:
    st.session_state.anonymized_content = ""
if 'detected_matches' not in st.session_state:
    st.session_state.detected_matches = []
if 'whitelist' not in st.session_state:
    st.session_state.whitelist = set()
if 'session_whitelist' not in st.session_state:
    st.session_state.session_whitelist = set()
if 'blacklist' not in st.session_state:
    st.session_state.blacklist = {}
if 'session_blacklist' not in st.session_state:
    st.session_state.session_blacklist = {}
if 'custom_token_types' not in st.session_state:
    st.session_state.custom_token_types = {}

def generate_token(category, index):
    """Generate semantic tokens with fixed prefixes + custom types"""
    import random
    import string
    
    random.seed(f"{category}_{index}_{st.session_state.session_id}")
    chars = string.ascii_uppercase + string.digits
    suffix = ''.join(random.choice(chars) for _ in range(4))
    
    # Fixed prefix mapping for essential categories
    prefix_map = {
        'EMAIL': 'EML', 'PHONE': 'PHN', 'SSN': 'SSN', 'CREDIT_CARD': 'CRD',
        'ADDRESS': 'ADR', 'PERSON_NAME': 'PER', 'IP_ADDRESS': 'IPV', 'URL': 'URL',
        'COMPANY': 'COM', 'ACCOUNT_ID': 'ACC', 'ZIP_CODE': 'ZIP', 'DATE': 'DTE'
    }
    
    # Check custom types first
    if category in st.session_state.custom_token_types:
        prefix = st.session_state.custom_token_types[category]
    else:
        prefix = prefix_map.get(category, category[:3].upper())
    
    return f"[{prefix}{index:02d}{suffix}]"

def get_all_token_types():
    """Get all available token types (built-in + custom)"""
    built_in = ['EMAIL', 'PHONE', 'SSN', 'CREDIT_CARD', 'ADDRESS', 'PERSON_NAME', 
               'IP_ADDRESS', 'URL', 'COMPANY', 'ACCOUNT_ID', 'ZIP_CODE', 'DATE']
    custom = list(st.session_state.custom_token_types.keys())
    return built_in + custom

def is_token_type_in_use(token_type):
    """Check if a custom token type is currently being used"""
    if not st.session_state.token_mappings:
        return False
    
    if token_type in st.session_state.custom_token_types:
        prefix = st.session_state.custom_token_types[token_type]
        for token in st.session_state.token_mappings.values():
            if token.startswith(f"[{prefix}"):
                return True
    
    return False

def detect_sensitive_content(text):
    """Detect essential PII, technical, and business information + blacklist matches"""
    patterns = [
        ('EMAIL', r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        ('PHONE', r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
        ('SSN', r'\b\d{3}-\d{2}-\d{4}\b'),
        ('CREDIT_CARD', r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
        ('ADDRESS', r'\b\d+\s+(?:N|S|E|W|North|South|East|West|NE|NW|SE|SW)?\s*[A-Za-z\s]{1,40}?(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|Ct|Court|Pl|Place|Way|Ln|Lane|Pkwy|Parkway|Cir|Circle)\.?\b'),
        ('PERSON_NAME', r'\b[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\b'),
        ('IP_ADDRESS', r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
        ('URL', r'https?://[^\s<>"{}|\\^`\[\]]+'),
        ('COMPANY', r'\b[A-Z][A-Za-z\s&]{2,30}\s+(?:Corp|Corporation|Inc|Incorporated|LLC|Ltd|Limited|Company|Co\.|LP|LLP|PC|Enterprises|Group|Holdings|Partners|Associates|Solutions|Systems|Technologies|Tech|Consulting|Services|Industries|International|Worldwide)\b'),
        ('ACCOUNT_ID', r'\b(?:Account|ID|Ref|Reference)[\s#:]*([A-Z0-9]{6,})\b'),
        ('ZIP_CODE', r'\b\d{5}(?:-\d{4})?\b'),
        ('DATE', r'\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12][0-9]|3[01])[\/\-](?:19|20)\d{2}\b'),
    ]
    
    matches = []
    claimed_regions = []
    
    # FIRST PASS: Blacklist matches (HIGHEST PRIORITY)
    all_blacklist = {**st.session_state.blacklist, **st.session_state.session_blacklist}
    
    for blacklist_word, category in all_blacklist.items():
        start_pos = 0
        while True:
            pos = text.find(blacklist_word, start_pos)
            if pos == -1:
                break
            
            start, end = pos, pos + len(blacklist_word)
            
            # Blacklist always wins - no overlap check needed
            claimed_regions.append((start, end))
            matches.append({
                'category': category,
                'value': blacklist_word,
                'start': start,
                'end': end,
                'source': 'blacklist'
            })
            
            start_pos = pos + 1
    
    # SECOND PASS: Auto-detection patterns (lower priority)
    for category, pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            start, end = match.start(), match.end()
            
            # Check for overlaps with blacklist matches
            overlaps = any(not (end <= claimed_start or start >= claimed_end) 
                          for claimed_start, claimed_end in claimed_regions)
            
            if not overlaps:
                claimed_regions.append((start, end))
                matches.append({
                    'category': category,
                    'value': match.group().strip(),
                    'start': start,
                    'end': end,
                    'source': 'auto-detect'
                })
    
    matches.sort(key=lambda x: x['start'])
    return matches

def anonymize_text(text, approved_matches, category_overrides, word_selections):
    """Apply anonymization with word-level selection and category overrides"""
    final_mappings = {}
    token_counter = {}
    
    # Initialize counters for all categories
    all_categories = get_all_token_types()
    for category in all_categories:
        token_counter[category] = 0
    
    # Build replacement items
    replacement_items = []
    for i, match in enumerate(approved_matches):
        if match:
            words = match['value'].split()
            selected_words = []
            
            # Get selected words only
            for j, word in enumerate(words):
                if word_selections.get(i, {}).get(j, True):
                    selected_words.append(word)
            
            if selected_words:
                selected_text = ' '.join(selected_words)
                category = category_overrides.get(i, match['category'])
                
                if selected_text not in final_mappings:
                    token_counter[category] += 1
                    token = generate_token(category, token_counter[category])
                    final_mappings[selected_text] = token
                
                replacement_items.append({
                    'start': match['start'],
                    'end': match['end'],
                    'token': final_mappings[selected_text],
                    'original_words': words,
                    'word_selections': word_selections.get(i, {}),
                    'selected_text': selected_text
                })
    
    # Apply replacements (reverse order)
    replacement_items.sort(key=lambda x: x['start'], reverse=True)
    anonymized = text
    
    for item in replacement_items:
        start = item['start']
        end = item['end']
        words = item['original_words']
        selections = item['word_selections']
        token = item['token']
        
        # Build replacement text with word-level granularity
        result_parts = []
        token_added = False
        
        for j, word in enumerate(words):
            if selections.get(j, True):
                if not token_added:
                    result_parts.append(token)
                    token_added = True
            else:
                result_parts.append(word)
        
        replacement_text = ' '.join(result_parts)
        anonymized = anonymized[:start] + replacement_text + anonymized[end:]
    
    return anonymized, final_mappings

def generate_context_paragraph(mappings):
    """Generate context paragraph explaining token meanings for AI"""
    if not mappings:
        return ""
    
    # Group tokens by category
    token_categories = {}
    for original, token in mappings.items():
        if token.startswith('[') and token.endswith(']'):
            prefix = token[1:4]
            
            prefix_to_category = {
                'EML': 'Email addresses', 'PHN': 'Phone numbers', 'SSN': 'Social Security numbers',
                'CRD': 'Credit card numbers', 'ADR': 'Street addresses', 'PER': 'Person names',
                'IPV': 'IP addresses', 'URL': 'Website URLs', 'COM': 'Company names',
                'ACC': 'Account identifiers', 'ZIP': 'ZIP codes', 'DTE': 'Dates'
            }
            
            # Add custom token types
            for token_type, custom_prefix in st.session_state.custom_token_types.items():
                prefix_to_category[custom_prefix] = f"{token_type.replace('_', ' ').title()}s"
            
            category_name = prefix_to_category.get(prefix, f"Items with prefix {prefix}")
            
            if category_name not in token_categories:
                token_categories[category_name] = prefix
    
    if not token_categories:
        return ""
    
    # Build context paragraph
    context_lines = [
        "CONTEXT FOR AI ANALYSIS:",
        "The following document has been anonymized for privacy protection. Each token type represents:"
    ]
    
    for category, prefix in sorted(token_categories.items()):
        context_lines.append(f"- [{prefix}##XXXX] tokens represent {category}")
    
    context_lines.extend([
        "Please maintain awareness of these categories when analyzing the content below.",
        "=" * 60,
        ""
    ])
    
    return "\n".join(context_lines)

def deanonymize_text(text, mappings):
    """Restore original content"""
    restored = text
    reverse_mappings = {v: k for k, v in mappings.items()}
    
    for token, original in reverse_mappings.items():
        restored = restored.replace(token, original)
    
    return restored

# Streamlit UI
st.title("🔒 Document Anonymizer")
st.subheader("Protect PII, Technical Data & Business Information")

# Session info
st.sidebar.write(f"**Session ID:** `{st.session_state.session_id}`")

# Whitelist/Blacklist info
st.sidebar.markdown("---")
st.sidebar.subheader("📚 Learning Lists")
st.sidebar.write(f"**Whitelist:** {len(st.session_state.whitelist)} + {len(st.session_state.session_whitelist)}")
st.sidebar.write(f"**Blacklist:** {len(st.session_state.blacklist)} + {len(st.session_state.session_blacklist)}")

if st.sidebar.button("📋 View Lists"):
    st.session_state.show_lists = True

# Quick add to whitelist
st.sidebar.subheader("🛡️ Add to Whitelist")
whitelist_word = st.sidebar.text_input("Word to never detect:", placeholder="e.g., MyCompany", key="whitelist_word")
col_a, col_b = st.sidebar.columns(2)
with col_a:
    if st.sidebar.button("➕ Persistent", key="add_whitelist_persistent") and whitelist_word:
        st.session_state.whitelist.add(whitelist_word.lower())
        st.sidebar.success(f"Added '{whitelist_word}' to persistent whitelist!")
        st.rerun()
with col_b:
    if st.sidebar.button("➕ Session", key="add_whitelist_session") and whitelist_word:
        st.session_state.session_whitelist.add(whitelist_word.lower())
        st.sidebar.success(f"Added '{whitelist_word}' to session whitelist!")
        st.rerun()

# Quick add to blacklist
st.sidebar.subheader("⚫ Add to Blacklist")
blacklist_word = st.sidebar.text_input("Word to always detect:", placeholder="e.g., SecretProject", key="blacklist_word")
blacklist_category = st.sidebar.selectbox("Token Type:", get_all_token_types(), key="blacklist_category")
col_a, col_b = st.sidebar.columns(2)
with col_a:
    if st.sidebar.button("⚫ Persistent", key="add_blacklist_persistent") and blacklist_word:
        st.session_state.blacklist[blacklist_word] = blacklist_category
        st.sidebar.success(f"Added '{blacklist_word}' as {blacklist_category}!")
        st.rerun()
with col_b:
    if st.sidebar.button("⚫ Session", key="add_blacklist_session") and blacklist_word:
        st.session_state.session_blacklist[blacklist_word] = blacklist_category
        st.sidebar.success(f"Added '{blacklist_word}' as {blacklist_category}!")
        st.rerun()

# Show what we protect
st.sidebar.markdown("---")
st.sidebar.subheader("🛡️ Protection Categories")
st.sidebar.write("**Auto-Detected:**")
st.sidebar.write("Emails, Phones, SSNs, Cards, Addresses, Names, IPs, URLs, Companies, Account IDs, ZIP Codes, Dates")

st.sidebar.write("**Custom Types:** (Blacklist only)")
if st.session_state.custom_token_types:
    for token_type, prefix in st.session_state.custom_token_types.items():
        st.sidebar.write(f"- {token_type} → `[{prefix}##XXXX]`")
else:
    st.sidebar.write("None defined yet")

# Custom token type management
st.sidebar.markdown("---")
st.sidebar.subheader("➕ Add Custom Token Type")

with st.sidebar.expander("Create New Type"):
    new_type_name = st.text_input("Type Name:", placeholder="e.g., PRODUCT_ID", key="new_type_name")
    new_type_prefix = st.text_input("Prefix (1-4 chars):", placeholder="e.g., PRD", key="new_type_prefix", max_chars=4)
    
    if st.button("Add Custom Type", key="add_custom_type"):
        if new_type_name and new_type_prefix:
            if len(new_type_prefix) > 4:
                st.error("Prefix must be 4 characters or less")
            elif new_type_name.upper() in get_all_token_types():
                st.error("Type already exists")
            elif not new_type_prefix.isalnum():
                st.error("Prefix must be letters/numbers only")
            else:
                st.session_state.custom_token_types[new_type_name.upper()] = new_type_prefix.upper()
                st.success(f"Added {new_type_name.upper()} → {new_type_prefix.upper()}")
                st.rerun()
        else:
            st.error("Please enter both name and prefix")

# Remove custom token type
if st.session_state.custom_token_types:
    with st.sidebar.expander("Remove Custom Type"):
        type_to_remove = st.selectbox("Select type:", list(st.session_state.custom_token_types.keys()), key="remove_type_select")
        
        if st.button("Remove Type", key="remove_custom_type"):
            if is_token_type_in_use(type_to_remove):
                st.error(f"Can't remove {type_to_remove} - currently in use")
            else:
                del st.session_state.custom_token_types[type_to_remove]
                st.success(f"Removed {type_to_remove}")
                st.rerun()

# Session management
if st.sidebar.button("🆕 New Session"):
    st.session_state.session_id = str(uuid.uuid4())[:8]
    st.session_state.token_mappings = {}
    st.session_state.anonymized_content = ""
    st.session_state.session_whitelist = set()
    st.session_state.session_blacklist = {}
    # Clear detection state
    for key in ['detected_matches', 'approved_matches', 'word_selections', 'category_overrides']:
        if key in st.session_state:
            del st.session_state[key]
    st.sidebar.success("New session started!")
    st.rerun()

# Show whitelist/blacklist management if requested
if getattr(st.session_state, 'show_lists', False):
    st.header("📚 Whitelist & Blacklist Management")
    
    list_tab1, list_tab2 = st.tabs(["🛡️ Whitelist", "⚫ Blacklist"])
    
    with list_tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Persistent Whitelist")
            if st.session_state.whitelist:
                whitelist_df = pd.DataFrame(sorted(st.session_state.whitelist), columns=['Words'])
                st.dataframe(whitelist_df, use_container_width=True)
            else:
                st.info("No persistent whitelist words yet.")
        
        with col2:
            st.subheader("Session Whitelist") 
            if st.session_state.session_whitelist:
                session_df = pd.DataFrame(sorted(st.session_state.session_whitelist), columns=['Words'])
                st.dataframe(session_df, use_container_width=True)
                
                if st.button("📤 Move to Persistent"):
                    st.session_state.whitelist.update(st.session_state.session_whitelist)
                    count = len(st.session_state.session_whitelist)
                    st.session_state.session_whitelist.clear()
                    st.success(f"Moved {count} words to persistent whitelist!")
                    st.rerun()
            else:
                st.info("No session whitelist words yet.")
    
    with list_tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Persistent Blacklist")
            if st.session_state.blacklist:
                blacklist_df = pd.DataFrame(
                    [(word, cat) for word, cat in sorted(st.session_state.blacklist.items())],
                    columns=['Word', 'Category']
                )
                st.dataframe(blacklist_df, use_container_width=True)
            else:
                st.info("No persistent blacklist words yet.")
        
        with col2:
            st.subheader("Session Blacklist")
            if st.session_state.session_blacklist:
                session_blacklist_df = pd.DataFrame(
                    [(word, cat) for word, cat in sorted(st.session_state.session_blacklist.items())],
                    columns=['Word', 'Category']
                )
                st.dataframe(session_blacklist_df, use_container_width=True)
                
                if st.button("📤 Move to Persistent", key="move_blacklist"):
                    st.session_state.blacklist.update(st.session_state.session_blacklist)
                    count = len(st.session_state.session_blacklist)
                    st.session_state.session_blacklist.clear()
                    st.success(f"Moved {count} words to persistent blacklist!")
                    st.rerun()
            else:
                st.info("No session blacklist words yet.")
    
    if st.button("❌ Close List View"):
        st.session_state.show_lists = False
        st.rerun()

# Main tabs
tab1, tab2, tab3 = st.tabs(["📝 Anonymize", "☁️ Process", "🔓 De-anonymize"])

with tab1:
    st.header("Step 1: Anonymize Documents")
    
    st.info("**Auto-detects:** Emails, Phone Numbers, SSNs, Credit Cards, URLs, IP Addresses, ZIP Codes, Dates, Street Addresses, Person Names, Company Names, Account IDs")
    
    # File upload
    uploaded_file = st.file_uploader("Upload document", type=['txt'])
    
    # Text input
    input_text = st.text_area("Or paste content here:", height=200, 
                              placeholder="Paste your document content...")
    
    if st.button("🔍 Detect Sensitive Content", type="primary"):
        content = ""
        if uploaded_file:
            try:
                content = str(uploaded_file.read(), "utf-8")
            except:
                st.error("Could not read file")
        elif input_text:
            content = input_text
        
        if content:
            st.session_state.detected_matches = detect_sensitive_content(content)
            st.session_state.original_content = content
            st.success(f"Found {len(st.session_state.detected_matches)} potential items")
    
    # Review detected items
    if st.session_state.detected_matches:
        st.subheader("📋 Review Detected Items")
        st.write("Select items to anonymize and choose specific words:")
        
        # Initialize session state
        if 'approved_matches' not in st.session_state:
            st.session_state.approved_matches = [True] * len(st.session_state.detected_matches)
        if 'word_selections' not in st.session_state:
            st.session_state.word_selections = {}
            for i, match in enumerate(st.session_state.detected_matches):
                words = match['value'].split()
                st.session_state.word_selections[i] = {j: True for j in range(len(words))}
        if 'category_overrides' not in st.session_state:
            st.session_state.category_overrides = {}
        
        category_options = get_all_token_types()
        
        # Display items
        for i, match in enumerate(st.session_state.detected_matches):
            col1, col2, col3, col4 = st.columns([1, 3, 2, 2])
            
            with col1:
                st.session_state.approved_matches[i] = st.checkbox(
                    "Include", 
                    value=st.session_state.approved_matches[i] if i < len(st.session_state.approved_matches) else True,
                    key=f"approve_{i}"
                )
            
            with col2:
                st.write(f"`{match['value']}`")
                source = match.get('source', 'auto-detect')
                if source == 'blacklist':
                    st.write("🚫 Blacklist")
                else:
                    st.write("🔍 Auto-detect")
            
            with col3:
                current_category = st.session_state.category_overrides.get(i, match['category'])
                selected_category = st.selectbox(
                    "Category:",
                    category_options,
                    index=category_options.index(current_category) if current_category in category_options else 0,
                    key=f"category_{i}"
                )
                st.session_state.category_overrides[i] = selected_category
            
            with col4:
                if st.session_state.approved_matches[i]:
                    words = match['value'].split()
                    if len(words) > 1:
                        st.write("Select words:")
                        for j, word in enumerate(words):
                            st.session_state.word_selections[i][j] = st.checkbox(
                                word,
                                value=st.session_state.word_selections[i][j],
                                key=f"word_{i}_{j}"
                            )
                    else:
                        st.write("Single word")
                        st.session_state.word_selections[i] = {0: True}
        
        st.markdown("---")
        
        # Action buttons
        col1, col2, col3 = st.columns([1, 1, 1])
        
        with col1:
            if st.button("✅ Select All"):
                st.session_state.approved_matches = [True] * len(st.session_state.detected_matches)
                st.rerun()
        
        with col2:
            if st.button("❌ Deselect All"):
                st.session_state.approved_matches = [False] * len(st.session_state.detected_matches)
                st.rerun()
        
        with col3:
            if st.button("🔒 Apply Anonymization", type="primary"):
                if any(st.session_state.approved_matches):
                    # Learn from user selections
                    for i, match in enumerate(st.session_state.detected_matches):
                        if st.session_state.approved_matches[i]:
                            words = match['value'].split()
                            
                            # Add deselected words to whitelist
                            for j, word in enumerate(words):
                                if not st.session_state.word_selections[i].get(j, True):
                                    st.session_state.session_whitelist.add(word.lower())
                            
                            # Add selected words to blacklist
                            selected_words = []
                            for j, word in enumerate(words):
                                if st.session_state.word_selections[i].get(j, True):
                                    selected_words.append(word)
                            
                            if selected_words:
                                selected_text = ' '.join(selected_words)
                                category = st.session_state.category_overrides.get(i, match['category'])
                                st.session_state.session_blacklist[selected_text] = category
                        else:
                            # Add all words to whitelist
                            words = match['value'].split()
                            for word in words:
                                st.session_state.session_whitelist.add(word.lower())
                    
                    # Filter approved matches
                    approved = [match if approved else None 
                               for match, approved in zip(st.session_state.detected_matches, st.session_state.approved_matches)]
                    
                    # Anonymize
                    anonymized, mappings = anonymize_text(
                        st.session_state.original_content, 
                        approved, 
                        st.session_state.category_overrides,
                        st.session_state.word_selections
                    )
                    
                    st.session_state.anonymized_content = anonymized
                    st.session_state.token_mappings = mappings
                    
                    # Show learning summary
                    new_whitelist = len(st.session_state.session_whitelist)
                    new_blacklist = len(st.session_state.session_blacklist)
                    
                    if new_whitelist > 0:
                        st.success(f"✅ Added {new_whitelist} words to whitelist")
                    if new_blacklist > 0:
                        st.success(f"⚫ Added {new_blacklist} patterns to blacklist")
                    
                    st.success(f"🔒 Anonymized {len(mappings)} items!")
                    
                    # Clear detection state
                    del st.session_state.detected_matches
                    del st.session_state.approved_matches
                    del st.session_state.word_selections
                    del st.session_state.category_overrides
                    st.rerun()
                else:
                    st.error("Please select at least one item to anonymize")

    # Display results
    if st.session_state.anonymized_content:
        st.subheader("✅ Anonymized Content")
        
        # Generate context paragraph
        context_paragraph = generate_context_paragraph(st.session_state.token_mappings)
        
        # Combine context + anonymized content
        full_content = context_paragraph + "\n" + st.session_state.anonymized_content if context_paragraph else st.session_state.anonymized_content
        
        st.text_area("Ready for AI processing (includes context):", value=full_content, 
                    height=300, disabled=True)
        
        if context_paragraph:
            st.info("📝 **Context paragraph added** - explains token meanings to AI")
        
        if st.session_state.token_mappings:
            st.subheader("🔍 Token Mappings")
            mapping_df = pd.DataFrame(
                [(original, token) for original, token in st.session_state.token_mappings.items()],
                columns=['Original', 'Token']
            )
            st.dataframe(mapping_df, use_container_width=True)
        
        # Download buttons
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                "⬇️ Download with Context",
                data=full_content.encode('utf-8'),
                file_name=f"anonymized_with_context_{st.session_state.session_id}.txt",
                mime="text/plain"
            )
        
        with col2:
            if st.session_state.token_mappings:
                mapping_data = {
                    'session_id': st.session_state.session_id,
                    'timestamp': datetime.now().isoformat(),
                    'mappings': st.session_state.token_mappings,
                    'custom_token_types': st.session_state.custom_token_types
                }
                st.download_button(
                    "⬇️ Download Mappings",
                    data=json.dumps(mapping_data, indent=2),
                    file_name=f"mappings_{st.session_state.session_id}.json",
                    mime="application/json"
                )

with tab2:
    st.header("Step 2: Cloud Processing")
    st.info("""
    **Process:**
    1. Download anonymized content from Step 1
    2. Upload to your n8n/Claude workflow  
    3. Process with AI (semantic tokens preserve context)
    4. Download results
    5. Use Step 3 to restore original content
    """)

with tab3:
    st.header("Step 3: De-anonymize Results")
    
    # Upload results
    processed_file = st.file_uploader("Upload processed results", type=['txt'])
    processed_text = st.text_area("Or paste results:", height=200)
    
    # Upload mappings
    mappings_file = st.file_uploader("Upload mappings (if different session)", type=['json'])
    
    if st.button("🔓 Restore Original Content", type="primary"):
        content = ""
        if processed_file:
            try:
                content = str(processed_file.read(), "utf-8")
            except:
                st.error("Could not read file")
        elif processed_text:
            content = processed_text
        
        if content:
            # Use current mappings or load from file
            mappings = st.session_state.token_mappings
            
            if mappings_file:
                try:
                    mapping_data = json.loads(str(mappings_file.read(), "utf-8"))
                    mappings = mapping_data.get('mappings', {})
                    # Load custom types if available
                    if 'custom_token_types' in mapping_data:
                        st.session_state.custom_token_types.update(mapping_data['custom_token_types'])
                except:
                    st.error("Could not load mappings file")
            
            if mappings:
                restored = deanonymize_text(content, mappings)
                st.success("✅ Content restored!")
                st.text_area("Restored content:", value=restored, height=300, disabled=True)
                
                st.download_button(
                    "⬇️ Download Restored Content",
                    data=restored.encode('utf-8'),
                    file_name=f"restored_{st.session_state.session_id}.txt",
                    mime="text/plain"
                )
            else:
                st.error("No mappings available")
        else:
            st.error("Please provide content to restore")