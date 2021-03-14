Return-Path: <kasan-dev+bncBC33FCGW2EDRBT4AXKBAMGQE3LGNCHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B4AC33A834
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Mar 2021 22:29:52 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 74sf11737174ljj.3
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Mar 2021 14:29:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615757391; cv=pass;
        d=google.com; s=arc-20160816;
        b=bfU4KNjEmpNiKxKZB32VFbGBzubYRBha4nbX3wmLniz9RWLrtP2lHPM7qA4qndCaJs
         b5llruds/CgDZdfCz/WJUTq/PXvDTFJMELb9CMjDxl0QJ6MpqwuPeR8yz7W7GpVN7uB+
         J8vA2m6aYU+u7MFflppx5P8Fxi/HBOqtgRxuKmeDoByCyqqQ+vlrhl77+SsA/84MoHcC
         ksZuWkRARC5ut4a12+KU0hAVjCyiDSVycCqjMzEFVui4Bss5X806OhBbFHiUY7mqrUV/
         BwJT6e2bAGnBYmA7jHFLpXAnbzPHJ8Ii6mNBfEhLw67onVQa75aTgc96r3OKFRIRt8DF
         InZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=FRhyiAbUCQ/i+3KZFu8fASEh9KgXthF2aqrH5J2fjeM=;
        b=v5I12WnOByQZ7rJSR8LCyLGVZZ8wGOilGaJJpHqlu7PhqSEr9R1WNWey37SYG4r/x9
         51t1fQFiDpAIyILPd26zYQwAYtcoAEd3GkN/qUctENr0ge6QU1ELIh7WucF2zy15tPbu
         +qWeL9mDbiIoqY19BVpiiW/toxdrOThMQCD1740bDmetv6k2FkkmA/JYf3Uxr2Ai1e1G
         BOb93n5eE5hCSMhy/XWCJsPq7UMZNkCPNWReXnQaBUnC6N/YSksINhbK+eidOkaVNYlg
         8Q3gdlIyC4bJoOs7cMXTDA1QQudKnzjtk7QiwhjxhxR+ybxY3OEH9ECeAAGlasvzPH2Q
         e4PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b=QzHTLq7Y;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 188.68.63.166 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FRhyiAbUCQ/i+3KZFu8fASEh9KgXthF2aqrH5J2fjeM=;
        b=MRIE1+QpBGpeOjt6uboXjJH3v0fCovfhzHl9I5iW9kkZdZJpdJYL5Ny/dvWrzFJaNl
         7GcdSZoDOXvquwcvKLOaHxMszgwJntTLkXuybx+1KL+MVQX/7sjV+UTU1GErxh20qAYO
         SAvtj2IMXfyrKjTfZiV4k3rtOhbRUB8bOMKbxSF68owET6sHch2AKTB1In8ju+ICvt/K
         WvK6i2XGP6z9bD9PWoWpCh99Qlczk5M6NVdCLgJd47zJ7357X7zVqoACf7hJiV8sQ+Q6
         ihBMpbD+Fa6tHJhnp0xD+KxMtP6mKZKrbXRdtlJBLoEZMMaAH05s8Bz5aoVTgm4vd5Iy
         HIiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FRhyiAbUCQ/i+3KZFu8fASEh9KgXthF2aqrH5J2fjeM=;
        b=PimsYeVsNv74Og9TV/vRGvzwF4UetPYVC6jNSorim9XSA2aAV5DniExdnTAKFG6p3e
         chsILwtkdnttc9uZKy4omVXiJVOGngCDF1HU4s46Hlh00bqBKabc99gAMfo1j60nrDZW
         5drQDMKKSM3f4xMzzZFGw0Sue4CT2xi1goGDlOOhY5i7E7cTRvvcBHxVwmP5YY45Z6vr
         x5bDNKxC6lqr9/ogI6jz46yu3RQmobT3Bm1cIy//4fBWaga8HOWoMREF1opQMK4cmEkZ
         Bclr5y4cC6Ye+mpk0NSGNj/rO1d4HR3BXmOf/5nF6XKO8v72nxsDQq0OB7zYw7tI3/Eh
         Q3tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hJV2rIiUDedytyEWaa+5QlH2+MmdcwvGnbq8vv36rMKXCHs7A
	r71dtfFaYYfs2e3EwRsw1qE=
X-Google-Smtp-Source: ABdhPJyvCBYH9GG9OIlkl/pNgc2v5D9FYuqfHtNRoxvffAFQYwssO3Xj3PEeqom/hd3TlPAXY6y4zg==
X-Received: by 2002:a05:6512:1085:: with SMTP id j5mr6335108lfg.592.1615757391675;
        Sun, 14 Mar 2021 14:29:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls1933602lfo.0.gmail; Sun, 14 Mar
 2021 14:29:50 -0700 (PDT)
X-Received: by 2002:a05:6512:39c2:: with SMTP id k2mr5754031lfu.69.1615757390655;
        Sun, 14 Mar 2021 14:29:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615757390; cv=none;
        d=google.com; s=arc-20160816;
        b=GefubMKmziitYQ8cVZPIqfRGyepD2q6OLg+8JGvAAh20qEL6LVuDcOWE2rd2Fd9TGh
         CMQOANzAIWIufCo1v662eBNE/P8/SWjO1WRwly0JMFiNLPJZxQNXAHDqeBWrU/V671Br
         19nzaxebQh7HKNtgeCd9F22ndBsRW2q8He64xEIPz1Ao32wTsYnqYdoNrnk58btGigbv
         RAZN0pdglRVlcnPiPPstuBxTIHGelC+zwc94QeQeQCbJGYMa4gwsmJudUroa8IAbk7e7
         R3dqysLSPwaM6n+6T2WYF52l1CvKEgQmAaw/AhWsesIxJa2x47t4ki6vnkHS/FTl7/yC
         Elew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=tKkENpQ1VaGGolGjWP383V/ZruoBe9AWt7yWYqDfjdI=;
        b=UBKsErLsDB7JeJ4sYbqsHOMTBFmSl3tCOjgFQcGAqCb9bRPUNyFukRZPcloyrLow6i
         Rxfc7Hyco76E3pFV8AxdYoqJVehoiKNTkdkIWu1drqZ/f1dxVeGL9CdadeZrvzYoccx6
         kjS3U/fMzlsIWeWts42HU2GOD7wEZN1zdf1TYv7dI96X6hhw+wVNZ7YYZBuWvTV22/Z+
         ywz/i7OPvlAbL178H0Bzto01UGr5MNVTjzwAE0k5GoUEnVuI57/2nmiArPJPMiFFm/3Z
         tYPtwWYRyzvBeO3bDsW+VTD3MLLDWvKe79MwWm1FOxTpAVY3bmq4G01s0aXY/p54H649
         JHCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b=QzHTLq7Y;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 188.68.63.166 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
Received: from relay.yourmailgateway.de (relay.yourmailgateway.de. [188.68.63.166])
        by gmr-mx.google.com with ESMTPS id j12si382586lfg.8.2021.03.14.14.29.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 14 Mar 2021 14:29:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of info@alexander-lochmann.de designates 188.68.63.166 as permitted sender) client-ip=188.68.63.166;
Received: from mors-relay-8202.netcup.net (localhost [127.0.0.1])
	by mors-relay-8202.netcup.net (Postfix) with ESMTPS id 4DzCPT4ttsz4cKj;
	Sun, 14 Mar 2021 22:29:49 +0100 (CET)
Received: from policy01-mors.netcup.net (unknown [46.38.225.35])
	by mors-relay-8202.netcup.net (Postfix) with ESMTPS id 4DzCPT4HzXz4cKD;
	Sun, 14 Mar 2021 22:29:49 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at policy01-mors.netcup.net
X-Spam-Flag: NO
X-Spam-Score: -2.901
X-Spam-Level: 
X-Spam-Status: No, score=-2.901 required=6.31 tests=[ALL_TRUSTED=-1,
	BAYES_00=-1.9, SPF_PASS=-0.001] autolearn=ham autolearn_force=no
Received: from mx2e12.netcup.net (unknown [10.243.12.53])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by policy01-mors.netcup.net (Postfix) with ESMTPS id 4DzCPS00BLz8tGF;
	Sun, 14 Mar 2021 22:29:47 +0100 (CET)
Received: from [IPv6:2003:ed:7f1a:8ff0:bc4f:7872:30f9:5dc9] (p200300ed7f1a8ff0bc4f787230f95dc9.dip0.t-ipconnect.de [IPv6:2003:ed:7f1a:8ff0:bc4f:7872:30f9:5dc9])
	by mx2e12.netcup.net (Postfix) with ESMTPSA id 2C6D1A0792;
	Sun, 14 Mar 2021 22:29:46 +0100 (CET)
Received-SPF: pass (mx2e12: connection is authenticated)
Subject: Re: [PATCH] KCOV: Introduced tracing unique covered PCs
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet
 <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>,
 Wei Yongjun <weiyongjun1@huawei.com>,
 Maciej Grochowski <maciej.grochowski@pm.me>,
 kasan-dev <kasan-dev@googlegroups.com>,
 "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
 LKML <linux-kernel@vger.kernel.org>, syzkaller <syzkaller@googlegroups.com>
References: <20210211080716.80982-1-info@alexander-lochmann.de>
 <CACT4Y+YwRE=YNQYmQ=7RWde33830YOYr5pEAoYbrofY2JG43MA@mail.gmail.com>
From: Alexander Lochmann <info@alexander-lochmann.de>
Message-ID: <01a9177f-bfd5-251a-758f-d3c68bafd0cf@alexander-lochmann.de>
Date: Sun, 14 Mar 2021 22:29:45 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CACT4Y+YwRE=YNQYmQ=7RWde33830YOYr5pEAoYbrofY2JG43MA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: de-DE
X-PPP-Message-ID: <161575738654.15961.2097524548515925129@mx2e12.netcup.net>
X-PPP-Vhost: alexander-lochmann.de
X-NC-CID: JmTQRHjKDd5kGOW4U22LAUruP+XW8WLQK9Pb1HY7IfAcDGn68gXTIGqh
X-Original-Sender: info@alexander-lochmann.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alexander-lochmann.de header.s=key2 header.b=QzHTLq7Y;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates
 188.68.63.166 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
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



On 12.02.21 13:54, Dmitry Vyukov wrote:
> 
> I think we could make KCOV_IN_CTXSW sign bit and then express the check as:
> 
> void foo2(unsigned mode) {
>   if (((int)(mode & 0x8000000a)) > 0)
>     foo();
> }
> 
> 0000000000000020 <foo2>:
>   20: 81 e7 0a 00 00 80    and    $0x8000000a,%edi
>   26: 7f 08                jg     30 <foo2+0x10>
>   28: c3                    retq
> 
So ((int)(mode & (KCOV_IN_CTXSW | needed_mode))) > 0?
> 
> 
> 
>>  }
>>
>>  static notrace unsigned long canonicalize_ip(unsigned long ip)
>> @@ -191,18 +192,26 @@ void notrace __sanitizer_cov_trace_pc(void)
>>         struct task_struct *t;
>>         unsigned long *area;
>>         unsigned long ip = canonicalize_ip(_RET_IP_);
>> -       unsigned long pos;
>> +       unsigned long pos, idx;
>>
>>         t = current;
>> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
>> +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC | KCOV_MODE_UNIQUE_PC, t))
>>                 return;
>>
>>         area = t->kcov_area;
>> -       /* The first 64-bit word is the number of subsequent PCs. */
>> -       pos = READ_ONCE(area[0]) + 1;
>> -       if (likely(pos < t->kcov_size)) {
>> -               area[pos] = ip;
>> -               WRITE_ONCE(area[0], pos);
>> +       if (likely(t->kcov_mode == KCOV_MODE_TRACE_PC)) {
> 
> Does this introduce an additional real of t->kcov_mode?
> If yes, please reuse the value read in check_kcov_mode.
Okay. How do I get that value from check_kcov_mode() to the caller?
Shall I add an additional parameter to check_kcov_mode()?
> 
> 
>> +               /* The first 64-bit word is the number of subsequent PCs. */
>> +               pos = READ_ONCE(area[0]) + 1;
>> +               if (likely(pos < t->kcov_size)) {
>> +                       area[pos] = ip;
>> +                       WRITE_ONCE(area[0], pos);
>> +               }
>> +       } else {
>> +               idx = (ip - canonicalize_ip((unsigned long)&_stext)) / 4;
>> +               pos = idx % BITS_PER_LONG;
>> +               idx /= BITS_PER_LONG;
>> +               if (likely(idx < t->kcov_size))
>> +                       WRITE_ONCE(area[idx], READ_ONCE(area[idx]) | 1L << pos);
>>         }
>>  }
>>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
>> @@ -474,6 +483,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>>                 goto exit;
>>         }
>>         if (!kcov->area) {
>> +               kcov_debug("mmap(): Allocating 0x%lx bytes\n", size);
>>                 kcov->area = area;
>>                 vma->vm_flags |= VM_DONTEXPAND;
>>                 spin_unlock_irqrestore(&kcov->lock, flags);
>> @@ -515,6 +525,8 @@ static int kcov_get_mode(unsigned long arg)
>>  {
>>         if (arg == KCOV_TRACE_PC)
>>                 return KCOV_MODE_TRACE_PC;
>> +       else if (arg == KCOV_UNIQUE_PC)
>> +               return KCOV_MODE_UNIQUE_PC;
> 
> As far as I understand, users can first do KCOV_INIT_UNIQUE and then
> enable KCOV_TRACE_PC, or vice versa.
> It looks somewhat strange. Is it intentional? 
I'll fix that.
It's not possible to
> specify buffer size for KCOV_INIT_UNIQUE, so most likely the buffer
> will be either too large or too small for a trace.
No, the buffer will be calculated by KCOV_INIT_UNIQUE based on the size
of the text segment.

- Alex

-- 
Alexander Lochmann                PGP key: 0xBC3EF6FD
Heiliger Weg 72                   phone:  +49.231.28053964
D-44141 Dortmund                  mobile: +49.151.15738323

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01a9177f-bfd5-251a-758f-d3c68bafd0cf%40alexander-lochmann.de.
