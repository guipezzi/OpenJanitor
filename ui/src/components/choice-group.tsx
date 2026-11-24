import { RadioGroup } from 'radix-ui'

import { cn } from '@/lib/utils'

export interface Choice<T extends string> {
  value: T
  label: string
}

interface ChoiceGroupProps<T extends string> {
  /** The id of the element that names the group. */
  labelledBy: string
  value: T
  choices: Choice<T>[]
  onChange: (value: T) => void
  disabled?: boolean
}

/** A row of mutually exclusive choices: a radio group drawn as segments. */
export function ChoiceGroup<T extends string>({
  labelledBy,
  value,
  choices,
  onChange,
  disabled,
}: ChoiceGroupProps<T>) {
  return (
    <RadioGroup.Root
      aria-labelledby={labelledBy}
      value={value}
      onValueChange={(next) => onChange(next as T)}
      disabled={disabled}
      orientation="horizontal"
      className="inline-flex flex-wrap gap-1 rounded-lg border bg-muted/50 p-1"
    >
      {choices.map((choice) => (
        <RadioGroup.Item
          key={choice.value}
          value={choice.value}
          className={cn(
            'rounded-md px-3 py-1.5 text-sm text-muted-foreground outline-none',
            'hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50',
            'disabled:pointer-events-none disabled:opacity-50',
            'data-[state=checked]:bg-background data-[state=checked]:font-medium',
            'data-[state=checked]:text-foreground data-[state=checked]:shadow-sm',
          )}
        >
          {choice.label}
        </RadioGroup.Item>
      ))}
    </RadioGroup.Root>
  )
}
