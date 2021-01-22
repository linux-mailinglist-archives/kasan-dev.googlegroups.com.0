Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBSOPVOAAMGQEGRXBQFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 27E6C30064A
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:57:14 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id u8sf3991100qvm.5
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:57:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611327433; cv=pass;
        d=google.com; s=arc-20160816;
        b=qzv+8s1DFY7wNmEDrd0ZhfFfsgSLEH7sn+1cNtuuqyuh+0h4YqovosSM1JZripek2l
         TkmJFqi4JzCtQWJN6D+vMBjH1zWQ2B/Kr3zgKsd85rKVk03PbzUai9xUjX9nznvHiG5K
         6Y+N18AQQ7cgn5LWxDPaReouoYglMVwPHMU0ZK4+U34a/GJzo9BHVV8zwRNn5RkgdEtS
         x5oknW4UFSiXPQa93rLlF4jZlIRzWmkTUUVUsp/npQK7Yhbl2WsJQJ5l8FZJfGoZ9Q/E
         Sj5K3rVtionD54LViF9lwKx6xaH2axYhTpzV4XwUzsg2dAhphe2VShpvGiB51EFHggH/
         /xIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=X0gDmSolwxgTkvyQNuZFo0FDWpMIZBjq6WhSLSwpK/Q=;
        b=AdzCmF+JgOyg6Cwp/pxer7zymHiD2mv9zv0dcdIkg2BAmrilBrwFsCIelO7sA5lAnt
         NUNEDSso4woL7OaHIER77WCWEciFttVIMXnVfbzENXpVfQt9fqnUOJEKic9WeTWMY9oh
         Iu9Bk5jWlPwD5fmTXgJ0epsxuPXiXBkmJ5fEns6xg8fALKfN29VbnFGXxJ2l0HZPlaJu
         0JcvSh4ZcllAV2y1XhIiBfssd0NM6WVugL6oqWtCcSLz6Sex4XNyQU7OcdLw9/56r25T
         3RCDzhTZVgA/axL1HDAi/TV169ZR6Ja+kfd+qP0tK7O1W4HYKHk6QMT/XfNYIRF/a6nv
         aiTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=X0gDmSolwxgTkvyQNuZFo0FDWpMIZBjq6WhSLSwpK/Q=;
        b=tgVcMxS4snGRrlQv2I1Z9bYd1d2KDsyt3gl7bMx9bQ0DACtLYUJCrU7rjGCX5bEicz
         01jyuQA0ATKJQ3/m+JY1lKflfYLfToeZNE8bHE3sZpiUP3CKL4BcjTqWCEyB3PbVYk0k
         qnejPnJl+X0Nwe4Lt3MEg/rlPAY8K8GbAuYBxsOyJz+Z+CX1WGW6OOH/55GXdcP9s4v7
         lrMCxRZwIiKLj1gGgNbXKgdzq67ZZCr4hjrFETBM+vUkHIOEWcQ81xx9SJwt1aRHKoAk
         7zesUwNQBS7qMbwSntOWFaIJzSshk/pvAlrAvTRNqPMxSYk1IAz1ojaLI2lL6ZsrMvKX
         CHxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=X0gDmSolwxgTkvyQNuZFo0FDWpMIZBjq6WhSLSwpK/Q=;
        b=jiJ16vefHyeRfwKmHUEu+0NETfgcDk/2UCXUmYYTQMGW9aCwK3u+TxKyd5SXZ9YONt
         EMLWYVJ9KVPaJh9vuOIbQjZ+SrE6TtD0OuaLEgTb0CkKDpP4QgC7NLxyPYGdCCCJryDV
         t7WmqNn7g8M/ixA4Z1lG3Iewvc/4pL0/vb8S/6LCBAjq1cqt5fLC/0QVNfPTI/ulJPtl
         4GqTHofnkzDiw87ocjfQJ6BJ/orvvWYfDZXqXlXiFi62D+GIW2/tzKpIyjR63cTNWpyw
         kDfhEDjRr/80bT5D88pUlOBPG04m9nlX7+YEXgqf8ztlNpEvppBsJXbpa+2MVd5TmbGo
         55mA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fbQaNArh1FahjiL3Y1/lmYgShq24QfH4sVYpuJQMviEmIXYAw
	ufrWVuPQRMYBDGn6vraEbmM=
X-Google-Smtp-Source: ABdhPJwZRu2xcUwrdSQ/Y1p5Fd1GtJqLRUcHjPk6sJa+3OW/X7nByoyyNUpawtZlXeSziMz29gtBRg==
X-Received: by 2002:ac8:118c:: with SMTP id d12mr4688007qtj.262.1611327433273;
        Fri, 22 Jan 2021 06:57:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1001:: with SMTP id z1ls2265033qti.4.gmail; Fri, 22 Jan
 2021 06:57:12 -0800 (PST)
X-Received: by 2002:ac8:59d6:: with SMTP id f22mr4671716qtf.230.1611327432643;
        Fri, 22 Jan 2021 06:57:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611327432; cv=none;
        d=google.com; s=arc-20160816;
        b=jV2Au5jYJuAxVpgxwnvzYSBZ+7Izytu8xAyFQ9c9/qmOm21rcT8PgasumVPEgTlG3Z
         tFurocCn3Gs3p7188c3KzM2Aog2kWLx0lUjVVDJvM8ZU5AqC8zjvZMWL89Z5nwtF8Kw4
         4ngrgXaOcnvdO368HjMiPC3Dpai/6Pilcfdl7hpkhqWmXHOKZmzezoV6r8q1u8ISmEPW
         qepDaRF42mYws9o1bfXVJEpDo3fS5fknaomuLoQ3bRbIEmfXtVBL78ChBxuSqXWIWn7B
         H9GC1EpSZb6abnRRCESRnDWz/KDMheO8blARxsGTZbFxGTpxiEjBWJ+ZXpGI8im2XkvI
         z7uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=/CLdTb3SDGiUgTReaVss3CMemdXkf7z0HcdqAhfrmcg=;
        b=or/I77L0HNtzHJnpe5Mraxuqa1EcgbX10RVZzt/OqOCrry3tIsVtSacnhb/JdKPwq1
         YLxzJ/DwvzBs6raK15V7CrD8pN1/QWg+XVVHacmPA8KXV/AHjaJNBbMH48OW3msD/Bpb
         5VfYiMTpo7suCEDmtJtPRGms4ceiDoOn9XvuRHXIDC/VZKufjgeADlrhUpt4EL3C0Bt8
         mXqgSO/ZQsIm/rA2hslsxJiw8k/8RaOCdC2KHvB6ITuYpsj29s2gIA3Du3ri5ZaKKrc0
         od89BcmONsTHRh2OcqnXbMrj/BpnJTWNchv9umgbRYWYPVQVbCWsO+ovjYVwD2hxYSyc
         lVhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p6si802240qti.1.2021.01.22.06.57.12
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:57:12 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 465D911D4;
	Fri, 22 Jan 2021 06:57:12 -0800 (PST)
Received: from [10.37.8.28] (unknown [10.37.8.28])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 55A0A3F66E;
	Fri, 22 Jan 2021 06:57:10 -0800 (PST)
Subject: Re: [PATCH v7 3/4] kasan: Add report for async mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210122141125.36166-1-vincenzo.frascino@arm.com>
 <20210122141125.36166-4-vincenzo.frascino@arm.com>
 <CAAeHK+ydhzfrdrPbjok20rgMEYykpfmjcRASm_bTfhuTVXF_VA@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <42b4d820-0a33-35a0-0dd0-0381dd693b9e@arm.com>
Date: Fri, 22 Jan 2021 15:01:01 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+ydhzfrdrPbjok20rgMEYykpfmjcRASm_bTfhuTVXF_VA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 1/22/21 2:42 PM, Andrey Konovalov wrote:
> On Fri, Jan 22, 2021 at 3:11 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> KASAN provides an asynchronous mode of execution.
>>
>> Add reporting functionality for this mode.
>>
>> Cc: Dmitry Vyukov <dvyukov@google.com>
>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>> Cc: Alexander Potapenko <glider@google.com>
>> Cc: Andrey Konovalov <andreyknvl@google.com>
>> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  include/linux/kasan.h |  2 ++
>>  mm/kasan/report.c     | 13 +++++++++++++
>>  2 files changed, 15 insertions(+)
>>
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index bb862d1f0e15..b0a1d9dfa85c 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -351,6 +351,8 @@ static inline void *kasan_reset_tag(const void *addr)
>>  bool kasan_report(unsigned long addr, size_t size,
>>                 bool is_write, unsigned long ip);
>>
>> +void kasan_report_async(void);
>> +
>>  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>>
>>  static inline void *kasan_reset_tag(const void *addr)
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index 234f35a84f19..1390da06a988 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -358,6 +358,19 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>>         end_report(&flags);
>>  }
>>
>> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> 
> This looks wrong, CONFIG_KASAN_SW_TAGS doesn't use MTE, so this
> function isn't needed for that mode.
>

It is true, I will fix in v8.

> Let's add an #ifdef CONFIG_KASAN_HW_TAGS section in
> include/linux/kasan.h after the HW/SW one with kasan_report(). And
> only leave CONFIG_KASAN_HW_TAGS in mm/kasan/report.c too.
> 
>> +void kasan_report_async(void)
>> +{
>> +       unsigned long flags;
>> +
>> +       start_report(&flags);
>> +       pr_err("BUG: KASAN: invalid-access\n");
>> +       pr_err("Asynchronous mode enabled: no access details available\n");
>> +       dump_stack();
>> +       end_report(&flags);
>> +}
>> +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>> +
>>  static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>>                                 unsigned long ip)
>>  {
>> --
>> 2.30.0
>>

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/42b4d820-0a33-35a0-0dd0-0381dd693b9e%40arm.com.
