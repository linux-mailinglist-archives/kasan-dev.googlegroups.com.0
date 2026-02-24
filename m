Return-Path: <kasan-dev+bncBAABBA6W6XGAMGQE4QIHPIQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id OJxEIwZrnWnhPwQAu9opvQ
	(envelope-from <kasan-dev+bncBAABBA6W6XGAMGQE4QIHPIQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 10:10:30 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1122D1844A9
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 10:10:29 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-385bb7f429csf28004581fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 01:10:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771924229; cv=pass;
        d=google.com; s=arc-20240605;
        b=eYwU2WO5BpWCHFSQF5b+Tq4fPVetkDp1+gYSEPmRVa8rqtHyOv6t9Fhm4uKpPi1i7R
         bNdVMndmOu3x2EvQN8duH+ARDz8CjRN/SESWnKcDOMZFpWongrNww3O3Eeu3gGgKAcug
         E7SIg/SSVdgP4LOQToZPRdnPLmyKMIDMNGFWdUsKxSOqGAflHl5i/uWpjSXMEQd/sl1u
         C6Cv0VHtaTgwgJcLfP/4puIbWbqwjmsQXkdfiEb4I+OrzQlU3vz9W4PgsRAQhPA/eXuU
         2e506d8uUJPAPf4onm7QtKIJg2IAWo74wpbE2EiqJJ7xDTAY1Yoc/1FTsQqbSZTUqEje
         7spw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=Yx5SJYs5UzCCEYVELS0CJvnGWAW5yFFOt8FbvxKhCto=;
        fh=Ev7ak1XcVLE7TBo6gEwr4YD5b+k9RW+1o2tf9FQxUaY=;
        b=i0LZhgEPNbIEtZBh0Z0lrDrwpCSzcG5ByTDzEeGI0D8P73XoN07cmLPf/++903LnPZ
         qJuvJPHWPMajyWIVwYqqzgcflk8zRNLCYU8000wrtshY9DBTuVfxZaomyLFVTEA5sUNN
         3xIhmzyEqrfe6M+QvtyvB5uKzPrb8JMKautDAKn5K6XRrEhrcq4K3EcO+kWQrIhk8Hat
         6iTfwtBhNM1E/UWs1NVFXQkuskwUcNV3CShvsq6t/wVU7WwQCogKwIVrXc41cAVhEBw6
         nuXnuLPT2EdUXwbzT0XupAFFY+gDVLBSMNRnn51JUwKrAUcqrwyIlFmwAHPgnljRnZaG
         2Oag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="dWJ/DG0g";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.100 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771924229; x=1772529029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Yx5SJYs5UzCCEYVELS0CJvnGWAW5yFFOt8FbvxKhCto=;
        b=Xy1ffDPQcuMaQGZm4VNrj6BtQka4ftjAlfOZyLyFnBetE4ylN+aVoF+vWjdvHOTSPY
         qQaM6wXi5DGu09EiDJ7aagBsnGXhMZnPXnJxNg4/U+4E8ZA5872tir4splQkCqa1M5Iu
         qqXSBaB1tdfPw7ehYFnPOfuT2KN4qQ2XryLncoZ5KdOChcJL6y9z3Y2jEFvWmf0RrVOq
         nhSEbvcIDIgj8SU7jlJsVV72KHpd9wxf+deO0k4jiBpdWa2BUDa9vDe7qKlmgtHvzP6i
         aM+Wx33xibGNuX6f+2mX99wqU2FxF78t3c4bEsgDOMSgU3zLy91SGpuz8i95TepgaixE
         xd9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771924229; x=1772529029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Yx5SJYs5UzCCEYVELS0CJvnGWAW5yFFOt8FbvxKhCto=;
        b=VrixCEJhSwoKxqaYw7foSJw0msgIL+4E8PWjlEPkzSidQnLUV289a7zog6997YIOJj
         uvGngi7aAb2qzgHVlz8rqJBjc6UrBaFquvduZenxp+dunFQtqqU6m/qcSWPZ4BzyGgdg
         dkhOH176N4R4FerPzHQi7jqufAh8oZNnDKm5vl1/M5SAorJs/3USDzSde01evvZytZKR
         1wLS1xHSIiPflS2Bs1E7AAM2HJprZZX+9iC1f1sWq3iRexFN/ohLo7v8DwW6pj2Bmtbn
         MGPRe4t3ovBfLENRWjmhjwxZOOno74hgCUuYHAwwT6dLw/vQbQnQ+NOn5dJU99F2ZQWi
         wiEA==
X-Forwarded-Encrypted: i=2; AJvYcCWwID7vnnMp4d0gwl1QpzA8w2Rr+MtZUz5kliqckzRio59X6YQJCgS+uagVBqFFDIkOjZOABA==@lfdr.de
X-Gm-Message-State: AOJu0YxVgQQHNVkkVcPf7k+cbgxsMmIlKH+w1/dcb45ODiz1YKuY+XtI
	OW308NCd0Z6PmH7nljBwBCAMnUHAmdUyBBlZsrSHyOBE+t/2vH+b3L6G
X-Received: by 2002:ac2:4e0c:0:b0:59e:459c:15f7 with SMTP id 2adb3069b0e04-5a0ed8825e1mr3731969e87.14.1771924228585;
        Tue, 24 Feb 2026 01:10:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GZykVx2kA8Vu0xfJ1N1yKmMtAEnvtjpgXiMWJjBe+6mg=="
Received: by 2002:a05:6512:3d18:b0:59b:6d6e:9887 with SMTP id
 2adb3069b0e04-59e651d793bls4164099e87.0.-pod-prod-02-eu; Tue, 24 Feb 2026
 01:10:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWfeo3LbNPWpOwYEjuQys14Jc/Wt2kA0tiFrznK23od8hbqxGt1L+L1K6eDV9eHXjLhVe3c4dkc35w=@googlegroups.com
X-Received: by 2002:a05:6512:15a6:b0:59d:fac0:3a11 with SMTP id 2adb3069b0e04-5a0ed9af47dmr3729387e87.45.1771924226205;
        Tue, 24 Feb 2026 01:10:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771924226; cv=none;
        d=google.com; s=arc-20240605;
        b=VAS+0qZKbgIhTpyqc32aMjEOEOBHuGl1pIh9YcZa3I0w2Ru+vYFgtaZaeE67a3aY0Y
         /ykyNfE2jIga3P/YK3VwMlRMzNV9mJlj5BQljsRl2V5asrH4fZyMit9PcUdcijPcHYiC
         SHWrFeeAIlPN/DYv82BhcUHs/6GxidyVkwbDJjxO2cYk7NFYlNzWRLajylBBmNdtRQ1k
         iBV1YFuJPU3NEu6a2wNv7Y4YpHLswzxhfXAUUH06T45hAqGAchrmDpun0AYeiqt22OH9
         cbehyTea95LZumTufD9hSU2IpktSRiGqNCj17j5bhqha2XpiEc0kuSlWF9Ydzx0GnrYB
         yhrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=JTNnUecjMCgQWBRNlhXYFdQDFTHMCliRoDTga/EjldQ=;
        fh=RX1FTpF6ubPqdGvhXch2v/H0LMQINDgb+rxI7yVCgzc=;
        b=FYod3XafFnJTndFjTgkzb+cZJbX41x4rZjSzfl1z+1RfRcGTYqjwP3vosdcHzmm2tv
         yfJ0NxYsvwWSA41BUg8xjCQcwlSLg0fL61oRdSf2N8uVT3ibckmdM+SwxZ0b7yz+A+mP
         CXwBKpaKC71ZNSFSsM6BW0fJK/Q24DcrZqB4e08DmLYQpS/EknD9Hy6BMBpLHgsFI11p
         hUx9hYegpW97ZiQYbeC3x8jmuwisbHzqmOLGTdyIe4pXPlymXAFjWH6UWPyldwxlvmQg
         6RMKmU2v5P0KCgroLGi4vp0Q1GG/8oJl0f0UsAAFTd0P606WwcAhB+5lErR5VtGoRWg5
         PAVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="dWJ/DG0g";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.100 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-43100.protonmail.ch (mail-43100.protonmail.ch. [185.70.43.100])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-389a7a04132si2537151fa.7.2026.02.24.01.10.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Feb 2026 01:10:26 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.100 as permitted sender) client-ip=185.70.43.100;
Date: Tue, 24 Feb 2026 09:10:18 +0000
To: Dave Hansen <dave.hansen@intel.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org, kasan-dev@googlegroups.com, workflows@vger.kernel.org
Subject: Re: [PATCH v10 13/13] x86/kasan: Make software tag-based kasan available
Message-ID: <aZ1qOpMc9PohArcL@wieczorr-mobl1.localdomain>
In-Reply-To: <f25c328f-4ce7-4494-a200-af4ba928e724@intel.com>
References: <cover.1770232424.git.m.wieczorretman@pm.me> <8fd6275f980b90c62ddcb58cfbc78796c9fa7740.1770232424.git.m.wieczorretman@pm.me> <f25c328f-4ce7-4494-a200-af4ba928e724@intel.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 263b095a4846ac376e793435bbda706f4f4065b0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="dWJ/DG0g";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.100 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBAABBA6W6XGAMGQE4QIHPIQ];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	FREEMAIL_CC(0.00)[kernel.org,redhat.com,alien8.de,linux.intel.com,zytor.com,lwn.net,gmail.com,google.com,arm.com,infradead.org,linux-foundation.org,intel.com,vger.kernel.org,googlegroups.com];
	RCPT_COUNT_TWELVE(0.00)[21];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[wieczorr-mobl1.localdomain:mid,pm.me:replyto,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 1122D1844A9
X-Rspamd-Action: no action

On 2026-02-23 at 12:52:03 -0800, Dave Hansen wrote:
>...
>> diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x=
86/x86_64/mm.rst
>> index a6cf05d51bd8..7e2e4c5fa661 100644
>> --- a/Documentation/arch/x86/x86_64/mm.rst
>> +++ b/Documentation/arch/x86/x86_64/mm.rst
>> @@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
>>     ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unu=
sed hole
>>     ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual=
 memory map (vmemmap_base)
>>     ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unu=
sed hole
>> -   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN s=
hadow memory
>> +   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN s=
hadow memory (generic mode)
>> +   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN s=
hadow memory (software tag-based mode)
>>    __________________|____________|__________________|_________|________=
____________________________________________________
>>                                                                |
>>                                                                | Identic=
al layout to the 56-bit one from here on:
>> @@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
>>     ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unu=
sed hole
>>     ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual=
 memory map (vmemmap_base)
>>     ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unu=
sed hole
>> -   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN s=
hadow memory
>> +   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN s=
hadow memory (generic mode)
>> +   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN s=
hadow memory (software tag-based mode)
>>    __________________|____________|__________________|_________|________=
____________________________________________________
>
>I think the idea of these is that you can run through, find *one* range
>and know what a given address maps to. This adds overlapping ranges.
>Could you make it clear that part of the area is "generic mode" only and
>the other part is for generic mode and for "software tag-based mode"?

Boris suggested adding a footnote to clarify these are alternative ranges [=
1].
Perhaps I can add a star '*' next to these two so it can notify someone to =
look for
the footnote?

[1] https://lore.kernel.org/all/20260113161047.GNaWZuh21aoxqtTNXS@fat_crate=
.local/

>
>> @@ -176,5 +178,9 @@ Be very careful vs. KASLR when changing anything her=
e. The KASLR address
>>  range must not overlap with anything except the KASAN shadow area, whic=
h is
>>  correct as KASAN disables KASLR.
>>
>> +The 'KASAN shadow memory (generic mode)/(software tag-based mode)' rang=
es are
>> +mutually exclusive and depend on which KASAN setting is chosen:
>> +CONFIG_KASAN_GENERIC or CONFIG_KASAN_SW_TAGS.
>> +
>>  For both 4- and 5-level layouts, the KSTACK_ERASE_POISON value in the l=
ast 2MB
>>  hole: ffffffffffff4111
>> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools=
/kasan.rst
>> index 64dbf8b308bd..03b508ebe673 100644
>> --- a/Documentation/dev-tools/kasan.rst
>> +++ b/Documentation/dev-tools/kasan.rst
>> @@ -22,8 +22,8 @@ architectures, but it has significant performance and =
memory overheads.
>>
>>  Software Tag-Based KASAN or SW_TAGS KASAN, enabled with CONFIG_KASAN_SW=
_TAGS,
>>  can be used for both debugging and dogfood testing, similar to userspac=
e HWASan.
>> -This mode is only supported for arm64, but its moderate memory overhead=
 allows
>> -using it for testing on memory-restricted devices with real workloads.
>> +This mode is only supported for arm64 and x86, but its moderate memory =
overhead
>> +allows using it for testing on memory-restricted devices with real work=
loads.
>>
>>  Hardware Tag-Based KASAN or HW_TAGS KASAN, enabled with CONFIG_KASAN_HW=
_TAGS,
>>  is the mode intended to be used as an in-field memory bug detector or a=
s a
>> @@ -351,10 +351,12 @@ Software Tag-Based KASAN
>>  Software Tag-Based KASAN uses a software memory tagging approach to che=
cking
>>  access validity. It is currently only implemented for the arm64 archite=
cture.
>>
>> -Software Tag-Based KASAN uses the Top Byte Ignore (TBI) feature of arm6=
4 CPUs
>> -to store a pointer tag in the top byte of kernel pointers. It uses shad=
ow memory
>> -to store memory tags associated with each 16-byte memory cell (therefor=
e, it
>> -dedicates 1/16th of the kernel memory for shadow memory).
>> +Software Tag-Based KASAN uses the Top Byte Ignore (TBI) feature of arm6=
4 CPUs to
>> +store a pointer tag in the top byte of kernel pointers. Analogously to =
TBI on
>> +x86 CPUs Linear Address Masking (LAM) feature is used and the pointer t=
ag is
>> +stored in four bits of the kernel pointer's top byte. Software Tag-Base=
d mode
>> +uses shadow memory to store memory tags associated with each 16-byte me=
mory cell
>> +(therefore, it dedicates 1/16th of the kernel memory for shadow memory)=
.
>
>This is going to get really cumbersome really fast if all the
>architectures doing this add their marketing terms in here.
>
>	Software Tag-Based KASAN uses the hardware CPU features* to
>	repurpose space inside kernel pointers to store pointer tags.
>	...
>
>and then _elsewhere_ you can describe the two implementations.

Okay, I'll rewrite that.

>
>>  On each memory allocation, Software Tag-Based KASAN generates a random =
tag, tags
>>  the allocated memory with this tag, and embeds the same tag into the re=
turned
>> @@ -370,12 +372,14 @@ Software Tag-Based KASAN also has two instrumentat=
ion modes (outline, which
>>  emits callbacks to check memory accesses; and inline, which performs th=
e shadow
>>  memory checks inline). With outline instrumentation mode, a bug report =
is
>>  printed from the function that performs the access check. With inline
>> -instrumentation, a ``brk`` instruction is emitted by the compiler, and =
a
>> -dedicated ``brk`` handler is used to print bug reports.
>> -
>> -Software Tag-Based KASAN uses 0xFF as a match-all pointer tag (accesses=
 through
>> -pointers with the 0xFF pointer tag are not checked). The value 0xFE is =
currently
>> -reserved to tag freed memory regions.
>> +instrumentation, arm64's implementation uses the ``brk`` instruction em=
itted by
>> +the compiler, and a dedicated ``brk`` handler is used to print bug repo=
rts. On
>> +x86 inline mode doesn't work yet due to missing compiler support.
>> +
>> +For arm64 Software Tag-Based KASAN uses 0xFF as a match-all pointer tag
>> +(accesses through pointers with the 0xFF pointer tag are not checked). =
The value
>> +0xFE is currently reserved to tag freed memory regions. On x86 the same=
 tags
>> +take on 0xF and 0xE respectively.
>
>I think this would be more clear with a table or list of features and
>supported architectures.

That is a good idea, I'll work on that

>
>>  Hardware Tag-Based KASAN
>>  ~~~~~~~~~~~~~~~~~~~~~~~~
>> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
>> index 80527299f859..877668cd5deb 100644
>> --- a/arch/x86/Kconfig
>> +++ b/arch/x86/Kconfig
>> @@ -67,6 +67,7 @@ config X86
>>  	select ARCH_CLOCKSOURCE_INIT
>>  	select ARCH_CONFIGURES_CPU_MITIGATIONS
>>  	select ARCH_CORRECT_STACKTRACE_ON_KRETPROBE
>> +	select ARCH_DISABLE_KASAN_INLINE	if X86_64 && KASAN_SW_TAGS
>>  	select ARCH_ENABLE_HUGEPAGE_MIGRATION if X86_64 && HUGETLB_PAGE && MIG=
RATION
>>  	select ARCH_ENABLE_MEMORY_HOTPLUG if X86_64
>>  	select ARCH_ENABLE_MEMORY_HOTREMOVE if MEMORY_HOTPLUG
>> @@ -196,6 +197,8 @@ config X86
>>  	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>  	select HAVE_ARCH_KASAN			if X86_64
>>  	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
>> +	select HAVE_ARCH_KASAN_SW_TAGS		if ADDRESS_MASKING && CC_IS_CLANG
>> +	select ARCH_NEEDS_DEFER_KASAN		if ADDRESS_MASKING
>>  	select HAVE_ARCH_KFENCE
>>  	select HAVE_ARCH_KMSAN			if X86_64
>>  	select HAVE_ARCH_KGDB
>> @@ -410,6 +413,7 @@ config AUDIT_ARCH
>>  config KASAN_SHADOW_OFFSET
>>  	hex
>>  	depends on KASAN
>> +	default 0xeffffc0000000000 if KASAN_SW_TAGS
>>  	default 0xdffffc0000000000
>
>Please separate this from the documentation.

Okay, I'll split the documentation part into a separate patch.

>
>>  config HAVE_INTEL_TXT
>> diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/=
misc.h
>> index fd855e32c9b9..ba70036c2abd 100644
>> --- a/arch/x86/boot/compressed/misc.h
>> +++ b/arch/x86/boot/compressed/misc.h
>> @@ -13,6 +13,7 @@
>>  #undef CONFIG_PARAVIRT_SPINLOCKS
>>  #undef CONFIG_KASAN
>>  #undef CONFIG_KASAN_GENERIC
>> +#undef CONFIG_KASAN_SW_TAGS
>>
>>  #define __NO_FORTIFY
>>
>> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
>> index 90c18e30848f..53ab7de16517 100644
>> --- a/arch/x86/include/asm/kasan.h
>> +++ b/arch/x86/include/asm/kasan.h
>> @@ -6,7 +6,12 @@
>>  #include <linux/kasan-tags.h>
>>  #include <linux/types.h>
>>  #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>> +
>> +#ifdef CONFIG_KASAN_SW_TAGS
>> +#define KASAN_SHADOW_SCALE_SHIFT 4
>> +#else
>>  #define KASAN_SHADOW_SCALE_SHIFT 3
>> +#endif
>>
>>  /*
>>   * Compiler uses shadow offset assuming that addresses start
>> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
>> index 7f5c11328ec1..8cbb8ec32061 100644
>> --- a/arch/x86/mm/kasan_init_64.c
>> +++ b/arch/x86/mm/kasan_init_64.c
>> @@ -465,4 +465,9 @@ void __init kasan_init(void)
>>
>>  	init_task.kasan_depth =3D 0;
>>  	kasan_init_generic();
>> +
>> +	if (cpu_feature_enabled(X86_FEATURE_LAM))
>> +		kasan_init_sw_tags();
>> +	else
>> +		pr_info("KernelAddressSanitizer not initialized (sw-tags): hardware d=
oesn't support LAM\n");
>>  }
>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>> index a4bb610a7a6f..d13ea8da7bfd 100644
>> --- a/lib/Kconfig.kasan
>> +++ b/lib/Kconfig.kasan
>> @@ -112,7 +112,8 @@ config KASAN_SW_TAGS
>>
>>  	  Requires GCC 11+ or Clang.
>>
>> -	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
>> +	  Supported on arm64 CPUs that support Top Byte Ignore and on x86 CPUs
>> +	  that support Linear Address Masking.
>
>Can this read more like:
>
>	Supported on:
>		arm64: CPUs with Top Byte Ignore
>		x86:   CPUs with Linear Address Masking.
>
>please?

Sure, I'll change it.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
Z1qOpMc9PohArcL%40wieczorr-mobl1.localdomain.
