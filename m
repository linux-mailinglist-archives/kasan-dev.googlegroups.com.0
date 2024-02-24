Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKO75CXAMGQEDPPFIEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B3B8862690
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 19:04:27 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-6e4c4b47fc8sf1212297b3a.2
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 10:04:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708797866; cv=pass;
        d=google.com; s=arc-20160816;
        b=AGkN8+w+kwPbgP+QfLTkulQsAK/2uaJEOUxyFhouEPQdgPQhgrf5FxcFCXP2D5bcTN
         pW/ZVsgJSVMFfd5ygS88f1R2nRamkzSDaKYmo4KZrtZPKAFp02hJFKe9E4qTojAaGOS7
         aI9xVC/uEboOUoR2SaumsQ3D3LxxsAmykOCXfLnrH+4VqfnTwvVZF9yFUMr2VhA7tTSn
         l2FFT4e/kCvsDw7IdjRc8pUjogGxihv/O0cLiIls5ndTUaG8nhuJfwA57vVqHmrTjvcx
         Rb9xE6RnP8M9057NlQg39zsiNBP/kUkOD4mPRvLYBT2W2RD2xkeosIRAfn/D46QdBhp7
         F9Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Cxy0mncCQP7otTTCd8zcvPMfhaS8lUMwQ4ptxZdiD3Y=;
        fh=Qa8WzfHzNDpLuCroBEbZUtFsF+QgSBUBXn4yN2Iu7lA=;
        b=r9rZnv89Xx38HZEQ2h7PLdy541zfCYoH0/LofeacGHuoIhT/u6nOQyW8+81MN1cmMn
         OItEpnaz+1IVADYjsbWnv05lQK6Dj82qfH8D2pSFl/1CsCtkyl2jGdGkVoBeTs1dw41X
         6oTV0UA8MrhtNLhM05S76tF2pcJuzj/2u+Iua1H6rnqrIUHWzUzp3gtbUWV6+EqFxyYK
         nPwF5rEXPKv/i0fX39xisGXEQFlYLpiZYtOkHgoWz5Z6EjJo7mjXcTOLgdH4DnuOiNQt
         DOpTq2foegv31F8lAY0yjjXwi5eSA+uzXvWcDsgQ49D4b6gbIsEQk+jETqFCz0g5xTcE
         i4OQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZHbK9ubX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708797866; x=1709402666; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Cxy0mncCQP7otTTCd8zcvPMfhaS8lUMwQ4ptxZdiD3Y=;
        b=rZbYpbbKXkbGELSB/KIuHSRKc00h6bCqxy+BQtWRI7L1LEPX9SMkejgmaSrH6DhTrL
         dKA9iIZ0PXp2KhXCNL/Mm0QGNYQBDAzFgcujtpcQCkeaJmQ6wTa9CVJw9g4fsHlflJae
         3SVW3LPbskew4/igXcxSz2EvwftkbTicPY0hLvlvcB+DpCI6QqUs5Bff7JwHwEM8Oxo1
         NsnP7F3kczKqE1Mak/s5MGw4en5L9rqcJDs90txXP/L7IByug7GE2awYCffwgj9d0lJ1
         FcVj6Hb4oyro8GM1KmLGEL3BiG69URo4dH6vKaiFVJ3ATCLOpiZpIXVYCC+Py6A+1sn7
         50/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708797866; x=1709402666;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Cxy0mncCQP7otTTCd8zcvPMfhaS8lUMwQ4ptxZdiD3Y=;
        b=DyLPBkXEnZ2gNQabcfmTvy8pk3zW3oTNPfqjdPG2IvdCQ5/BOuRWSEiUDs7NE5lhxJ
         PKFja5voPVY1VLdmdXfXYo3KlTD+/SAPomfvLtOt0RDJFkLzQuCIf+AiMGlTnd7rf7+B
         pEls7+pm/50in2pERax9o5JhPkHP7YddmRUdr51pYwmXYuODcwm/VOIYFseacQYP0GQ7
         OkgMn/Hub4LbDmMt7n7GMU01g7uJbaz1AekxhMUy6aCQv6BOyXdmX/m4bs0nV37fRJFc
         WXWr4AWae0SoNc/b5DJPkBpf8DOUuHeBkBYcPm8eRhNnqTgnVqFpmV2r57bR7fqsYplv
         dlMw==
X-Forwarded-Encrypted: i=2; AJvYcCVvdALqc38ShnhURFQn+bSyNYLyt0GsoULOF35XiANcQQduY3x6dV07BmQnKFDsKboKUFsrMdQ30Zc9NeyN/TlEMX85FBRRHA==
X-Gm-Message-State: AOJu0YznKpMOrGQ3fuIr5M+YxYWXG7oUIh33bDtrqoR7VZNcNi2Adzfr
	srj71nkvBMt2g6ds98V1SU+/X9WfQ6wknVI9spXVEpIE+mb9KOFT
X-Google-Smtp-Source: AGHT+IEhZFx9rM/ahWVs1KsKrbQNn412ikD09p/KrV+xh0hsMcytNwjkCHkHzpkywWZERdmyqdLRtw==
X-Received: by 2002:a62:8497:0:b0:6e4:4a26:1cbd with SMTP id k145-20020a628497000000b006e44a261cbdmr3153492pfd.2.1708797865754;
        Sat, 24 Feb 2024 10:04:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:6ca1:b0:6e4:eebe:efff with SMTP id
 jc33-20020a056a006ca100b006e4eebeefffls717821pfb.0.-pod-prod-02-us; Sat, 24
 Feb 2024 10:04:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUdCFBzh+9GAIcRScE2I65wt4Z2VtHcvb8QW5LFu8gi3Zxe2UwnHWNMZ3NSI7ByRP51XX+bgSBPyItf66dEsHEShiYrIYUUPQRP2w==
X-Received: by 2002:a05:6a21:3a82:b0:1a0:f3d0:15af with SMTP id zv2-20020a056a213a8200b001a0f3d015afmr927877pzb.34.1708797864235;
        Sat, 24 Feb 2024 10:04:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708797864; cv=none;
        d=google.com; s=arc-20160816;
        b=wTE3PX6m2kEhbHqJNWEpuTu6fpoCMkiGwNbelKwpn+gsPnP1ZNqOftDkL8JGMwCpTy
         sQp8nurAXPeHjCmDgUpnZttzTXXoQZHvEF5NaXneytayYyrEhIT+qMKFhxcLCSNilZ9w
         tAjESZVF59KVmbJhHXx+ZgvO3FNU54lYtgUDz/qO8UvV+a7S5dLE3zTX60gEsP+ffzs7
         qfzIDixIpWIlrZI8HNycCk+sYeSU0f/OlcAu3cgJo24XwcVWAIjGpmCl/Y/bZlMbxiZn
         l3EWsAoQc0hAINoCT4WI6OSSjvxVQIyOOY+eJZxEdXA/BeG9jcFCLmfdrY1As/MLBZI+
         Re8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=102AgdscnmlaS5ECv7WvZDiPmEMRao2nvjNOKWRVZbk=;
        fh=96iLRL8HWGJUWP/HA5C7iL/RiitNyVaNNmSYd8bY3VA=;
        b=hsbupWZYSga3a7cT+q+FO9k2EEE98ku+wnYtEf2HP6VYpugkzU2pukfZbUfjgF06fO
         xotcfJjU9vcMjiYig8zKO4NczHYfPxn5rkhpWawb4Hiu06b3x2oFZK8avOJslZWtcaXU
         f3kDRAgCYuK+uL3uQycXBymeeqhAQwsf+4m8cKkDp4/D4HeBy07pbZY4HALf3YBN0zbC
         rIcJCwMmZIGCwypflP9mx9tMa59uVNA7AKwy9gjvfuqmCMyxbztwHYOahduK6pK72XqL
         Y0XsQoTOo9/iyiahnDHW4ZuBmvzTlBE1zf93lZE9vS67/utcAntmkq44KHTcOjebc6Bd
         VfHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZHbK9ubX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id w17-20020a17090a8a1100b00299907bd50esi291389pjn.2.2024.02.24.10.04.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 24 Feb 2024 10:04:24 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id 46e09a7af769-6ddf26eba3cso1378692a34.0
        for <kasan-dev@googlegroups.com>; Sat, 24 Feb 2024 10:04:24 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVccTwaZh9UNku3k6jAPgCNAhOdu3xGXRuz/S2GsM2hZ6ioOX+PFtM7oIpiVQqEW2e3j0B6Ik26/l0K9+/wxE6ypfi1QvYGgmuWxA==
X-Received: by 2002:a05:6870:9589:b0:21f:d09e:b185 with SMTP id
 k9-20020a056870958900b0021fd09eb185mr2256417oao.42.1708797863322; Sat, 24 Feb
 2024 10:04:23 -0800 (PST)
MIME-Version: 1.0
References: <20240118110216.2539519-1-elver@google.com> <20240118110216.2539519-2-elver@google.com>
 <a1f0ebe6-5199-4c6c-97cb-938327856efe@I-love.SAKURA.ne.jp>
In-Reply-To: <a1f0ebe6-5199-4c6c-97cb-938327856efe@I-love.SAKURA.ne.jp>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 24 Feb 2024 19:03:44 +0100
Message-ID: <CANpmjNMY8_Qbh+QS3jR8JBG6QM6mc2rhNUhBtt2ssHNBLT1ttg@mail.gmail.com>
Subject: Re: [PATCH 2/2] stackdepot: make fast paths lock-less again
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Andi Kleen <ak@linux.intel.com>, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ZHbK9ubX;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Sat, 24 Feb 2024 at 12:38, Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> Hello, stackdepot developers.
>
> I suspect that commit 4434a56ec209 ("stackdepot: make fast paths
> lock-less again") is not safe, for
> https://syzkaller.appspot.com/x/error.txt?x=1409f29a180000 is reporting
> UAF at list_del() below from stack_depot_save_flags().
>
> ----------
> +       /*
> +        * We maintain the invariant that the elements in front are least
> +        * recently used, and are therefore more likely to be associated with an
> +        * RCU grace period in the past. Consequently it is sufficient to only
> +        * check the first entry.
> +        */
> +       stack = list_first_entry(&free_stacks, struct stack_record, free_list);
> +       if (stack->size && !poll_state_synchronize_rcu(stack->rcu_state))
> +               return NULL;
> +
> +       list_del(&stack->free_list);
> +       counters[DEPOT_COUNTER_FREELIST_SIZE]--;
> ----------
>
> Commit 4434a56ec209 says that race is handled by refcount_inc_not_zero(), but
> refcount_inc_not_zero() is called only if STACK_DEPOT_FLAG_GET is specified.

Correct. Because it is invalid stackdepot usage to have unbalanced GET
and stack_depot_put().

> ----------
> +       list_for_each_entry_rcu(stack, bucket, hash_list) {
> +               if (stack->hash != hash || stack->size != size)
> +                       continue;
>
> -       lockdep_assert_held(&pool_rwlock);
> +               /*
> +                * This may race with depot_free_stack() accessing the freelist
> +                * management state unioned with @entries. The refcount is zero
> +                * in that case and the below refcount_inc_not_zero() will fail.
> +                */
> +               if (data_race(stackdepot_memcmp(entries, stack->entries, size)))
> +                       continue;
>
> -       list_for_each(pos, bucket) {
> -               found = list_entry(pos, struct stack_record, list);
> -               if (found->hash == hash &&
> -                   found->size == size &&
> -                   !stackdepot_memcmp(entries, found->entries, size))
> -                       return found;
> +               /*
> +                * Try to increment refcount. If this succeeds, the stack record
> +                * is valid and has not yet been freed.
> +                *
> +                * If STACK_DEPOT_FLAG_GET is not used, it is undefined behavior
> +                * to then call stack_depot_put() later, and we can assume that
> +                * a stack record is never placed back on the freelist.
> +                */
> +               if ((flags & STACK_DEPOT_FLAG_GET) && !refcount_inc_not_zero(&stack->count))
> +                       continue;
> +
> +               ret = stack;
> +               break;
>         }
> ----------
>
> I worried that if we race when STACK_DEPOT_FLAG_GET is not specified,
> depot_alloc_stack() by error overwrites stack->free_list via memcpy(stack->entries, ...),
> and invalid memory access happens when stack->free_list.next is read.
> Therefore, I tried https://syzkaller.appspot.com/text?tag=Patch&x=17a12a30180000
> but did not help ( https://syzkaller.appspot.com/x/error.txt?x=1423a4ac180000 ).
>
> Therefore, I started to suspect how stack_depot_save() (which does not set
> STACK_DEPOT_FLAG_GET) can be safe. Don't all callers need to set STACK_DEPOT_FLAG_GET
> when calling stack_depot_save_flags() and need to call stack_depot_put() ?

stackdepot users who do not use STACK_DEPOT_FLAG_GET must never call
stack_depot_put() on such entries.

Violation of this contract will lead to UAF errors.

From the report I see this is a KMSAN error. There is a high chance
this is a false positive. Have you tried it with this patch:
https://lore.kernel.org/all/20240124173134.1165747-1-glider@google.com/T/#u

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMY8_Qbh%2BQS3jR8JBG6QM6mc2rhNUhBtt2ssHNBLT1ttg%40mail.gmail.com.
