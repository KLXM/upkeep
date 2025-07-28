# Add Domain-Mapping functionality to Upkeep AddOn

## 🎯 Overview

This PR adds comprehensive domain-mapping functionality to the Upkeep AddOn, allowing automatic redirects from specific domains to target URLs with configurable HTTP status codes.

## ✨ New Features

### 🔀 Domain-Mapping System
- **Individual Domain Redirects**: Map specific domains to target URLs
- **HTTP Status Code Support**: 301 (Permanent), 302 (Temporary), 303 (See Other), 307, 308
- **Global Toggle**: Central activation/deactivation for all domain mappings
- **Status Management**: Individual active/inactive control per mapping
- **URL Validation**: Automatic `https://` protocol addition for incomplete URLs

### 🖥️ Backend Interface
- **CRUD Operations**: Complete Create, Read, Update, Delete functionality
- **User-friendly Forms**: Clean interface for managing domain mappings
- **List View**: Overview of all mappings with search and filtering
- **Validation**: Domain and URL validation with error handling
- **Descriptions**: Optional descriptions for better organization

### 🔧 Technical Implementation
- **Early Execution**: Domain mapping runs before maintenance mode checks
- **Performance Optimized**: Minimal database queries, only on frontend
- **Clean Integration**: Seamless integration into existing Upkeep workflow
- **Status Indicator**: Gray "D" label in backend menu when active

## 🛠️ Technical Details

### Database Schema
```sql
CREATE TABLE rex_upkeep_domain_mapping (
    id int(10) unsigned NOT NULL AUTO_INCREMENT,
    domain varchar(255) NOT NULL,
    target_url text NOT NULL,
    http_code int(3) NOT NULL DEFAULT 301,
    status tinyint(1) NOT NULL DEFAULT 1,
    description text,
    createdate datetime NOT NULL,
    updatedate datetime NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY domain (domain)
);
```

### Code Changes
- **lib/Upkeep.php**: Added `checkDomainMapping()` method with global toggle
- **boot.php**: Integrated domain mapping check before maintenance checks  
- **install.php**: Database table creation with modern `rex_sql_table` API
- **pages/domain_mapping.php**: Complete backend interface (246 lines)
- **package.yml**: Added domain-mapping page configuration
- **lang/de_de.lang**: German language strings for UI
- **README.md**: Comprehensive documentation with examples

## 🎮 Usage Examples

### Permanent Domain Migration (SEO)
```
Domain: old-company.com
Target: https://new-company.com
HTTP Code: 301 (Permanent)
Status: Active
```

### Subdomain Redirect
```
Domain: blog.example.com  
Target: https://example.com/blog
HTTP Code: 301 (Permanent)
Status: Active
```

### Temporary Maintenance Redirect
```
Domain: shop.example.com
Target: https://example.com/maintenance  
HTTP Code: 302 (Temporary)
Status: Active
```

## 🚀 Benefits

- **SEO-Friendly**: Proper HTTP status codes for search engines
- **Flexible**: Support for temporary and permanent redirects
- **Easy Management**: Simple backend interface for non-technical users
- **Performance**: Minimal overhead, early execution
- **Maintainable**: Clean code integration with existing architecture

## 🔍 Testing

- ✅ Domain mapping creation and editing
- ✅ HTTP status code validation (301, 302, 303, 307, 308)
- ✅ URL validation and protocol handling
- ✅ Global toggle functionality  
- ✅ Status indicator in backend menu
- ✅ Database table creation and migration
- ✅ Frontend redirect execution
- ✅ Error handling and validation

## 📚 Documentation

The README has been updated with:
- Complete domain-mapping configuration guide
- HTTP status code reference table
- Real-world usage examples
- Best practices and tips
- Technical implementation details

## 🔄 Compatibility

- **REDAXO**: 5.10+ (uses modern `rex_sql_table` API)
- **PHP**: 8.0+ (uses modern PHP features like `str_starts_with()`)
- **Dependencies**: Core REDAXO only, no external dependencies
- **Backwards Compatible**: No breaking changes to existing functionality

## 🎨 UI/UX

- Consistent with REDAXO backend styling
- Bootstrap 3.x compatible forms and tables
- Clear visual feedback for active/inactive mappings
- Intuitive workflow for creating and managing redirects
- Help text and validation messages in German

---

This feature significantly extends the Upkeep AddOn's capabilities, making it a comprehensive solution for both maintenance mode management and domain redirection needs.
