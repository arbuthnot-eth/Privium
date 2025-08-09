// frontend/src/components/CopyButton.tsx
import { useState, useCallback } from 'react'

interface CopyButtonProps {
  textToCopy: string
  buttonText?: string
  className?: string
  onHoverChange?: (hovered: boolean) => void
}

export default function CopyToClipboardButton({ textToCopy, buttonText = 'Copy', className, onHoverChange }: CopyButtonProps) {
  const [isCopied, setIsCopied] = useState(false)
  
  const handleCopyClick = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(textToCopy)
      setIsCopied(true)
      setTimeout(() => setIsCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy text: ', err)
    }
  }, [textToCopy])
  
  const handleMouseEnter = useCallback(() => {
    onHoverChange?.(true)
  }, [onHoverChange])
  
  const handleMouseLeave = useCallback(() => {
    // Small delay to prevent flickering when moving between button and token
    setTimeout(() => onHoverChange?.(false), 50)
  }, [onHoverChange])
  
  return (
    <button
      className={className ?? 'btn btn-primary'}
      onClick={handleCopyClick}
      onPointerEnter={handleMouseEnter}
      onPointerLeave={handleMouseLeave}
    >
      {isCopied ? 'Copied!' : buttonText}
    </button>
  )
}