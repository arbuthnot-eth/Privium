// frontend/src/components/CopyButton.tsx
import { useState, useCallback } from 'react';

interface CopyButtonProps {
  textToCopy: string;
  buttonText?: string;
  highlightTargetId?: string;
}

export default function CopyToClipboardButton({ textToCopy, buttonText = 'Copy', highlightTargetId }: CopyButtonProps) {
  const [isCopied, setIsCopied] = useState(false);
  const [isHovered, setIsHovered] = useState(false);
  
  const handleCopyClick = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(textToCopy);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy text: ', err);
    }
  }, [textToCopy]);
  
  const handleMouseEnter = () => {
    setIsHovered(true);
    if (highlightTargetId) {
      const target = document.getElementById(highlightTargetId);
      if (target) {
        target.style.backgroundColor = 'rgba(255, 255, 255, 0.3)';
        target.style.color = '#ffffff';
        target.style.padding = '2px 4px';
        target.style.borderRadius = '3px';
        target.style.boxShadow = '0 0 5px rgba(255, 255, 255, 0.5)';
      }
    }
  };

  const handleMouseLeave = () => {
    setIsHovered(false);
    if (highlightTargetId) {
      const target = document.getElementById(highlightTargetId);
      if (target) {
        target.style.backgroundColor = '';
        target.style.color = '';
        target.style.padding = '';
        target.style.borderRadius = '';
        target.style.boxShadow = '';
      }
    }
  };
  
  return (
    <button
      onClick={handleCopyClick}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      style={{
        padding: '5px 10px',
        fontSize: '14px',
        cursor: 'pointer',
        backgroundColor: isHovered ? '#0056b3' : '#007bff',
        color: 'white',
        border: 'none',
        borderRadius: '4px'
      }}
    >
      {isCopied ? 'Copied!' : buttonText}
    </button>
  );
}