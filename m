Return-Path: <kasan-dev+bncBCP5L24CQ4FRB75GRSZAMGQEDSHOMPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id E0DC48C4D0E
	for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 09:32:16 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2e233a3d4b0sf55174361fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 00:32:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715671936; cv=pass;
        d=google.com; s=arc-20160816;
        b=MuKMfKcAC6EK0EaaUVAIEdPYvoXhOlrZLY3luSIvQi4JoNRpGCr1wpeZlolRpQjbL2
         xfNaz0uuS7GBZ+QTJXeXAhxhThR/bCq4PBYsDFfRe+8GFNgnWrQSfWAuGwlOmYFFCzSp
         fvR46zM/MyaJ8tUVZeDLlQSthjUgTBlSwlvSrHL/UbMzUSPQn0AKL8a3jfjGqNf/xpIi
         D8dzoJ3mRwjyBhoKXhpgWZaXCR7yz/eBPEbWSIEhmkrNWkKNk1cwrKv+sZ4/ceFi5uTj
         B3Wr5b1cs9ndlQ4W2Zdu9P1FxCTpsMd3EW28OfD54Lg5RgEgNrU8F1f8oaVo4bnpp29u
         uKyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=pa4GR5IvPLUl4GfEr8aOss6cVqA2PmhNcZbmEwWY0q0=;
        fh=+VxJ36QHtJVROMxxwK/dT6UPPu+LdrOBmBxNE8itBWU=;
        b=vzKXhk1UHqZDOXICJv9Ex3vIw9uqvcKZqJUSo8uN9PPkyIvPFNReO5DpSrlkjE4Uq0
         ZQ3KlTztczAnQvFZe8+hLj5i7WjHim+7O1geX6MZD0zF8t/r1uNleRU3dakWVs760fP5
         ixDsstIUXFznLkCU+qEdDANl5Zwn2FFeA1WGSSEioxJ8LLlcQBKAudegCTiz8Cq/jHue
         cgHiSN4W14XrMZyAsqc8IXho50U2VYDAB2ME1/SllQh72qrhAdfxWkisvmXE49M/YiPj
         Ivpo05VAnLjfPbKL/pTbw3aTEjpFSkbq8VSVwOin9+P/BI3CjJ3JCz7jXagBo5rHy9AM
         Kv+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of roberto.sassu@huaweicloud.com designates 14.137.139.46 as permitted sender) smtp.mailfrom=roberto.sassu@huaweicloud.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715671936; x=1716276736; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pa4GR5IvPLUl4GfEr8aOss6cVqA2PmhNcZbmEwWY0q0=;
        b=NWaog0/GYVSw9MZKMsR/HdrINBAKe3XIt5oHz30J3ZYtJH0vuCAoErpRX9O5pjkqxV
         5JqIf+smTeqPbipHiHlMEW96FcWgomvA6oXVsOcl0yvBUQYn/wDK+Q7jaKfrYoOrMal0
         NPsnYjEeDn784lV3bIakOUXw8gLaeE+GKJvBdVkpEm428vIzfyCj7k2fFza2rCPMhTRk
         lM11efza95Q3nGYIWzpgpkzJJuPLyTPPOfOmeV31g2w2jl+ASDtDvnReU2nKCrOBdZqX
         dzPsEbPEvmfronYc/mH8APOmnU1WpNpEYEGkV31WGsiRUt1HAw31DR2UZBusHkLndDqH
         /BKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715671936; x=1716276736;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=pa4GR5IvPLUl4GfEr8aOss6cVqA2PmhNcZbmEwWY0q0=;
        b=g8SOKewZwVZr1lyxCw9m2YLaGX7lHU8YN0nCDTixaWNr3uMK+N87S8to0ieJyxpe2H
         ASiqrN8uiLL/v1rki/TyZMwmrs+iMMbHYG8EjZM2Sx9Na7elLJ8lxQf8UGu99M2LbdB7
         H1C0HQFgPpUmRiGrcwLRWOuok9tm0gB+Iomv69Q5ZeKzwTsy2INIXxzDfiqiZX4YUiVY
         sZcCpjF34N1NCSmLEuKdax73Q8tBK7DJ/jfd3rYhbH0z72tfg++MCOlSifzG89nq82IK
         sIJnBwGMXjrc2CjNHQxi8eiU42Kiio5oPT7zXKLavMrISJ2gdxzZ9CmIH3pmgBWejNee
         LCbA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUxLBjS4WN5FCRHb9hxXxVkXVoiowl2+fjisqhTytOFa/RI2fDXTEs/SMhdgXjzn+8bLy3m3yQe7KFwtWEU0lvxw3MBB7UFjQ==
X-Gm-Message-State: AOJu0YzvvE468LLCdDpMunSoOVwZkvmFLl4LDT8tJuFUdbfJ7JdCHdt8
	8ABDVJ9fpH6wdHTK7K+arXZeu/vVnU7bmUr4PNyFm3C5cpilA235
X-Google-Smtp-Source: AGHT+IFW1J3Hf/FpM/f6nWUChHWG4s5m6OB5gzt5XE3CZaEylkwL1UNZhiU2PHwyO3GHvaIbSmT8pg==
X-Received: by 2002:a05:651c:1037:b0:2e3:7f19:7072 with SMTP id 38308e7fff4ca-2e51ff4eafcmr83974581fa.28.1715671935572;
        Tue, 14 May 2024 00:32:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1f8e:b0:418:9cf6:ba4d with SMTP id
 5b1f17b1804b1-41fc12f2ceels21429885e9.0.-pod-prod-03-eu; Tue, 14 May 2024
 00:32:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbEeyk0sDyUwCwo/oQwG+k7nxflpI0u1+kSLG/J8EgYDOTuHLwYAwQ6F5eZnK+d8DzRQdOGcVzChyjfvE89roQ+Wn5ApGdpkcSbg==
X-Received: by 2002:a05:600c:310d:b0:41b:f979:e359 with SMTP id 5b1f17b1804b1-41fead6dc04mr106217225e9.38.1715671933476;
        Tue, 14 May 2024 00:32:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715671933; cv=none;
        d=google.com; s=arc-20160816;
        b=S/yx5Jx0Eb3WetTrescgqrAROewko9325MXrEirFk5nk1FqqmWpl1Hl8/bNWNcVOa3
         ZUk4kf+n1MCFV9iUUR91ialzKXv8JuU8Nzor0zgyjaqWUgtP3f9bNCutUox7SpWjYKKG
         +LTdeUbmbeAY20wWAKBTPSxo86ApepCp/zPQBoCuUsCgC2+JXdU7JZt7qqHpzYjwX0fi
         fkJhYd8kqy+TeU9DojW+tAQ1Yh7YZuEchJ6BAuEvgNe122K0AIUvNusGstauihFb2TCK
         sKkWlG8nYa5SEsQ9ZkKrSgkWjTeKHWPS0BQO9rgwiHV3P/I3kqQTIH+87/QQlE+Y9H5g
         pz8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=KKC+zEd4gOICE4h4YuAxlyBl+WgCIU+GrZE3j1AoQvo=;
        fh=xLm5j6aiBfeRKx32tnk5Kwo5BRl1Mxd24fuBxgqxYik=;
        b=GYfuUjNMGzs2xy9FwbTJXJ5Bzsudsq/nhRbkGl5OaLwpGYk6nWUrxhbvMON1eJxb9w
         dKVxLQNYNr9Ix7gZzvwdVVNb6qTFPWrfPj3Iw7y4le6Nmre1l5EYHwSfR5NRP+FhpmEx
         I+I26yPmlJvZ7pVtCjifUsstSqhOzE+rq8pQLRU4xR5PBfnAag8Y5zW3LyNZY3SIHKCX
         PpWEWaw7ZRB0m4CZ6FtuJom/SaA3bE7nColgxpWirms9kTywWsc1nRh1hmmzyWdxNmZ2
         SsmLWjysE6FBjlZ/Gl5fafZb/XVC3nbVBXDa9u+r0kFlejly5h540kFCWguBx8uwdbXA
         k5Fg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of roberto.sassu@huaweicloud.com designates 14.137.139.46 as permitted sender) smtp.mailfrom=roberto.sassu@huaweicloud.com
Received: from frasgout13.his.huawei.com (frasgout13.his.huawei.com. [14.137.139.46])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-41fdfe566easi6693325e9.1.2024.05.14.00.32.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 May 2024 00:32:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of roberto.sassu@huaweicloud.com designates 14.137.139.46 as permitted sender) client-ip=14.137.139.46;
Received: from mail.maildlp.com (unknown [172.18.186.51])
	by frasgout13.his.huawei.com (SkyGuard) with ESMTP id 4VdngL4Hm7z9v7Hm
	for <kasan-dev@googlegroups.com>; Tue, 14 May 2024 15:15:10 +0800 (CST)
Received: from mail02.huawei.com (unknown [7.182.16.27])
	by mail.maildlp.com (Postfix) with ESMTP id A7644140489
	for <kasan-dev@googlegroups.com>; Tue, 14 May 2024 15:32:06 +0800 (CST)
Received: from [127.0.0.1] (unknown [10.204.63.22])
	by APP2 (Coremail) with SMTP id GxC2BwAXUCRnE0NmIbQfCA--.1339S2;
	Tue, 14 May 2024 08:32:05 +0100 (CET)
Message-ID: <0fbd907e411a10386bdef679864dd3d84f0fa3ad.camel@huaweicloud.com>
Subject: Re: [PATCH 0/3] kbuild: remove many tool coverage variables
From: Roberto Sassu <roberto.sassu@huaweicloud.com>
To: Kees Cook <keescook@chromium.org>, Masahiro Yamada <masahiroy@kernel.org>
Cc: linux-kbuild@vger.kernel.org, linux-arch@vger.kernel.org, 
 linux-kernel@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, Josh
 Poimboeuf <jpoimboe@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Peter Oberparleiter <oberpar@linux.ibm.com>,  Johannes Berg
 <johannes@sipsolutions.net>, kasan-dev@googlegroups.com,
 linux-hardening@vger.kernel.org
Date: Tue, 14 May 2024 09:31:47 +0200
In-Reply-To: <202405131136.73E766AA8@keescook>
References: <20240506133544.2861555-1-masahiroy@kernel.org>
	 <202405131136.73E766AA8@keescook>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.4-0ubuntu2
MIME-Version: 1.0
X-CM-TRANSID: GxC2BwAXUCRnE0NmIbQfCA--.1339S2
X-Coremail-Antispam: 1UD129KBjvJXoWxCw18Kw1fCF15ur4UGw45ZFb_yoW5GFWfpr
	WrJ3WqkFWY9r10yF9Ikw1IqF1Sk397uF1Ygr909rW5AF1j9r1vvrs5trs8Z34DCws2y3W0
	yrW7XFZavr4jvaUanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkjb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I20VC2zVCF04k2
	6cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rwA2F7IY1VAKz4
	vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Jr0_JF4l84ACjcxK6xIIjxv20xvEc7Cj
	xVAFwI0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVWUJVW8JwA2z4x0Y4vEx4A2jsIEc7CjxV
	AFwI0_Gr0_Gr1UM2AIxVAIcxkEcVAq07x20xvEncxIr21l5I8CrVACY4xI64kE6c02F40E
	x7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87Iv67AKxVWUJVW8JwAm72CE4IkC6x
	0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lFIxGxcIEc7CjxVA2Y2ka0xkIwI1l42xK82IYc2Ij
	64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxVWUJVWUGwC20s026x
	8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r4a6rW5MIIYrxkI7VAKI48JMIIF0xvE
	2Ix0cI8IcVAFwI0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26r4j6F4UMIIF0xvE42
	xK8VAvwI8IcIk0rVWrZr1j6s0DMIIF0xvEx4A2jsIE14v26r1j6r4UMIIF0xvEx4A2jsIE
	c7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x07UZ18PUUUUU=
X-CM-SenderInfo: purev21wro2thvvxqx5xdzvxpfor3voofrz/1tbiAQADBF1jj51HGAAAs1
X-Original-Sender: roberto.sassu@huaweicloud.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of roberto.sassu@huaweicloud.com designates 14.137.139.46
 as permitted sender) smtp.mailfrom=roberto.sassu@huaweicloud.com
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

On Mon, 2024-05-13 at 11:48 -0700, Kees Cook wrote:
> In the future can you CC the various maintainers of the affected
> tooling? :)
> 
> On Mon, May 06, 2024 at 10:35:41PM +0900, Masahiro Yamada wrote:
> > 
> > This patch set removes many instances of the following variables:
> > 
> >   - OBJECT_FILES_NON_STANDARD
> >   - KASAN_SANITIZE
> >   - UBSAN_SANITIZE
> >   - KCSAN_SANITIZE
> >   - KMSAN_SANITIZE
> >   - GCOV_PROFILE
> >   - KCOV_INSTRUMENT
> > 
> > Such tools are intended only for kernel space objects, most of which
> > are listed in obj-y, lib-y, or obj-m.
> 
> This is a reasonable assertion, and the changes really simplify things
> now and into the future. Thanks for finding such a clean solution! I
> note that it also immediately fixes the issue noticed and fixed here:
> https://lore.kernel.org/all/20240513122754.1282833-1-roberto.sassu@huaweicloud.com/

Yes, this patch set fixes the issue too.

Tested-by: Roberto Sassu <roberto.sassu@huawei.com>

Now UBSAN complains about misaligned address, such as:

[    0.150000][    T1] UBSAN: misaligned-access in kernel/workqueue.c:5514:3
[    0.150000][    T1] member access within misaligned address 0000000064c36f78 for type 'struct pool_workqueue'
[    0.150000][    T1] which requires 512 byte alignment
[    0.150000][    T1] CPU: 0 PID: 1 Comm: swapper Not tainted 6.9.0-dont-use-00003-g3b621c71dc5e #2244

But I guess this is for a separate thread.

Thanks

Roberto

> > The best guess is, objects in $(obj-y), $(lib-y), $(obj-m) can opt in
> > such tools. Otherwise, not.
> > 
> > This works in most places.
> 
> I am worried about the use of "guess" and "most", though. :) Before, we
> had some clear opt-out situations, and now it's more of a side-effect. I
> think this is okay, but I'd really like to know more about your testing.
> 
> It seems like you did build testing comparing build flags, since you
> call out some of the explicit changes in patch 2, quoting:
> 
> >  - include arch/mips/vdso/vdso-image.o into UBSAN, GCOV, KCOV
> >  - include arch/sparc/vdso/vdso-image-*.o into UBSAN
> >  - include arch/sparc/vdso/vma.o into UBSAN
> >  - include arch/x86/entry/vdso/extable.o into KASAN, KCSAN, UBSAN, GCOV, KCOV
> >  - include arch/x86/entry/vdso/vdso-image-*.o into KASAN, KCSAN, UBSAN, GCOV, KCOV
> >  - include arch/x86/entry/vdso/vdso32-setup.o into KASAN, KCSAN, UBSAN, GCOV, KCOV
> >  - include arch/x86/entry/vdso/vma.o into GCOV, KCOV
> >  - include arch/x86/um/vdso/vma.o into KASAN, GCOV, KCOV
> 
> I would agree that these cases are all likely desirable.
> 
> Did you find any cases where you found that instrumentation was _removed_
> where not expected?
> 
> -Kees
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0fbd907e411a10386bdef679864dd3d84f0fa3ad.camel%40huaweicloud.com.
