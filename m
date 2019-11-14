Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBPG4WXXAKGQE636UKOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 70A3EFC988
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 16:09:50 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id a3sf3999846pls.10
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 07:09:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573744188; cv=pass;
        d=google.com; s=arc-20160816;
        b=zuRb6lY57aUBYbNG0Z+B8mAQD8AgmM0ZGEtBneo8BCs9LqQsLF00DttVCk6C2nsOqy
         wVxVSoFMT5XZ/bshcQFWFIxOpvpAC8wgqQUVIyc8Sh9azX0DN/2Ozj7c1uZCqHXKeOuY
         pBg2CIYJGwhePH5TsFz4wnIb0UsmD4FVNksxBxfdXzg0BcdvYGmxO4lrg1bv9daKuV02
         7EaYsCNeO+mIInU8I4Ab7/Y6FQTWmyN9VswWZ2jW41ZJ73OmV3bvabDN5mYLOIquEaeP
         8sxVW3ZeJ3av7bSu4GORjc2lt5Z5WqY0mJm0mQJi+CxED5JDmReKT2TYyx1rOIQAdoLZ
         8New==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nWfGZvhQ28LuJdAvvKY9zBJSOm+Dp2xcQNcmdcSNzCE=;
        b=ezXlyRSRbgzzQaLK4ccJBUHjDiLmM3EWxDUz405ag5aLjqb17/KQFawDvjioA8ojYa
         NMyOm81KOpMNL30LPKpGgbeSKJhCl8dKAmdFzGmCF7tL7OdLAdxvUx4OWD8NoBDBtoZn
         FVs8KFsiYMb2a9r5qKYBYZaow1EvDLzOcwBMBMIe+HOQM9c9MCE2prrswT0TaXk6VfCU
         TNH38iJJBRXKCsVF5KTuCrURPAw9S3aeMasmbSagrslwxVOOLvbqMhFZkdVqdXqWhd18
         i0jKU6JJLkppwRGi8uwdQ9x1R38zMnbZWhgsIzeUQPCsmWm3QlX00EfiHvnBiCk+BviK
         RKlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TRASm3Bg;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nWfGZvhQ28LuJdAvvKY9zBJSOm+Dp2xcQNcmdcSNzCE=;
        b=pdO+ThNoSLW/9xNC1SHs5Qm07xL1r6f8Sol0BCh0DW/hgjMlu8CjyjafhEVRxy39t6
         vxQQbWshwJv8ahlNRDVRon5sPeuR77KiBj/p5xXPOxYRnbNXK6tl+jNmaWoBX0nRvIFp
         1K+dtrK64j6gNQCaTz1k4xi6HfaVTkin7xU9zzz6myILfoy3H2VBmNqunlS1W/WSdB5r
         Va9PpePBTAI7i0sDrqKq3lpi4oMtUniuLhZNNp+teN+FTt1DaK8oUJRsy0gIWx7NT7Nk
         Ua18ExJoGTcybiNvyDlWv5NkglcPKE76eeL84b5mJfqIhFdiLbbXmJasX+XI6B9DemTx
         cAvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nWfGZvhQ28LuJdAvvKY9zBJSOm+Dp2xcQNcmdcSNzCE=;
        b=awSTSODP+20ANuW4IvDj9/aucisQvF53a6e8ktWs0TtWlZTu07g3C+ejXJ0aQMcCve
         t9m690FqOX23rLPy4DG6VOBoyjAaD1EYrEsvOs5m6IJv2fM+RdMeApIrs/F7WaIZR3s7
         ZrI1lD/aWhwsqdW68ORPyOMEhTAe0+7G+Vl59dSsDtR4aFlWXxCQ/A2IPks9bAtpVoAr
         QupVOkDNvjZchG2Stu7ICjIjw2Jh/5W7us35isPi9wmn99fKsmecCQ9kzFSrRq/YRuRb
         sKAZiXXiwZ5tkTcGABy+7gX9hMFFoVB9kUAGqFBTngUTg2Vsb0uNyaERfz+gaIKVFaj7
         jCnA==
X-Gm-Message-State: APjAAAWGxo6X0ryCwvjK8WRU0rYFlYJxBVmHEm0BhvhazTkaWWCreIty
	pAzYYG10SRHOtOJyBSQThUs=
X-Google-Smtp-Source: APXvYqyJy7sCjUpURXaGOxmNGIdCzWJOK9E2r926fUsdJTllf2EPVzee5Um8XYsBqZMLTbYETV37hw==
X-Received: by 2002:a17:90a:8901:: with SMTP id u1mr3161428pjn.64.1573744188823;
        Thu, 14 Nov 2019 07:09:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:a50f:: with SMTP id v15ls798657pfm.14.gmail; Thu, 14 Nov
 2019 07:09:48 -0800 (PST)
X-Received: by 2002:a62:3786:: with SMTP id e128mr11784962pfa.11.1573744188398;
        Thu, 14 Nov 2019 07:09:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573744188; cv=none;
        d=google.com; s=arc-20160816;
        b=MtjVRY929Y3j2favfDYPS7gumZ0CV4RxyUta9Yq/4GAZXYXnTfIy3Ir+J5MjbTFtot
         r53zm3hzs/LRb7sAsDt6rDbmq6yRjoMKylBsWhW52nqleyo+wEW6TuAE/PypnkKwR5ki
         cAw4xtygUYB7u58gp/t3t8p7CqjpVtDI+Zqk2OUupq6RY8n6cAxEyE6dPJCJ+gdgKbAG
         0/lRb5AI1UrfU+oggShbL2JXyEao80vLI2iutRsKJKe7JSvTDFxDCxrbb674GA5bYztR
         +5YB1i/87Sbwq/SnlM/HkZXrx9s8q8URkWcX2tAI8iczOUaZpgfMJurjLsSFWVeQLjrk
         oJ5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hIZW0Esa7rqGtB6CSWRu4KOQZWOLmeyw5FeK9CvEfA4=;
        b=LZJdP922sCDFJE1VvBtE9zIy4tGo5yuhrWrJ5j45ObfNO1zW6PPZ+PUHFhrkbtjdhG
         dmZgDxXySuhWwc8c6YiO3iUYkVMUgmMtPvpv/kSuHVw2rrq5aNBOana7uOu6x0Z9VrdF
         fN/5WXQAlPHMSx7c7HI35iGiNJfb5EjVDqyc9/V/OMLxGV5P7CcaPq7HRSGL+czl9Zie
         Zja0I0Agoz1kDS5t3TW8F7niAvYlyVQEr84WHYXDLMs0fp/L5w+YjLMPHzOBIySwfIQM
         6ICB0iWCEaDJzwYkXDcqyZ7cTCsWVxRxEt3ffDSg5HUJvM8vktTHiTL8TI95G+FWmtNP
         yv+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TRASm3Bg;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id az8si449763pjb.3.2019.11.14.07.09.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 07:09:48 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id z25so5126736oti.5
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 07:09:48 -0800 (PST)
X-Received: by 2002:a9d:37e6:: with SMTP id x93mr8205287otb.183.1573744187224;
 Thu, 14 Nov 2019 07:09:47 -0800 (PST)
MIME-Version: 1.0
References: <20191112211002.128278-1-jannh@google.com> <20191112211002.128278-3-jannh@google.com>
 <CACT4Y+aojSsss3+Y2FB9Rw=OPxXgsFrGF0YiAJ9eo2wJM0ruWg@mail.gmail.com>
In-Reply-To: <CACT4Y+aojSsss3+Y2FB9Rw=OPxXgsFrGF0YiAJ9eo2wJM0ruWg@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Nov 2019 16:09:20 +0100
Message-ID: <CAG48ez11Bhd+76T2L9xF64TZQOeezJ9+9GApG2A7eA1hVfG3eA@mail.gmail.com>
Subject: Re: [PATCH 3/3] x86/kasan: Print original address on #GP
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TRASm3Bg;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Nov 13, 2019 at 11:11 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> On Tue, Nov 12, 2019 at 10:10 PM 'Jann Horn' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> > Make #GP exceptions caused by out-of-bounds KASAN shadow accesses easier
> > to understand by computing the address of the original access and
> > printing that. More details are in the comments in the patch.
[...]
> +Andrey, do you see any issues for TAGS mode? Or, Jann, did you test
> it by any chance?

No, I didn't - I don't have anything set up for upstream arm64 testing here.

> > +void kasan_general_protection_hook(unsigned long addr)
> >  {
> > -       if (val == DIE_GPF) {
> > -               pr_emerg("CONFIG_KASAN_INLINE enabled\n");
> > -               pr_emerg("GPF could be caused by NULL-ptr deref or user memory access\n");
> > -       }
> > -       return NOTIFY_OK;
> > -}
> > +       unsigned long orig_addr;
> > +       const char *addr_type;
> > +
> > +       if (addr < KASAN_SHADOW_OFFSET)
> > +               return;
>
> Thinking how much sense it makes to compare addr with KASAN_SHADOW_END...
> If the addr is > KASAN_SHADOW_END, we know it's not a KASAN access,
> but do we ever get GP on canonical addresses?

#GP can occur for various reasons, but on x86-64, if it occurs because
of an invalid address, as far as I know it's always non-canonical. The
#GP handler I wrote will check the address and only call the KASAN
hook if the address is noncanonical (because otherwise the #GP
occurred for some other reason).

> > -static struct notifier_block kasan_die_notifier = {
> > -       .notifier_call = kasan_die_handler,
> > -};
> > +       orig_addr = (addr - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT;
> > +       /*
> > +        * For faults near the shadow address for NULL, we can be fairly certain
> > +        * that this is a KASAN shadow memory access.
> > +        * For faults that correspond to shadow for low canonical addresses, we
> > +        * can still be pretty sure - that shadow region is a fairly narrow
> > +        * chunk of the non-canonical address space.
> > +        * But faults that look like shadow for non-canonical addresses are a
> > +        * really large chunk of the address space. In that case, we still
> > +        * print the decoded address, but make it clear that this is not
> > +        * necessarily what's actually going on.
> > +        */
> > +       if (orig_addr < PAGE_SIZE)
> > +               addr_type = "dereferencing kernel NULL pointer";
> > +       else if (orig_addr < TASK_SIZE_MAX)
> > +               addr_type = "probably dereferencing invalid pointer";
>
> This is access to user memory, right? In outline mode we call it
> "user-memory-access". We could say about "user" part here as well.

Okay, I'll copy that naming.

> > +       else
> > +               addr_type = "maybe dereferencing invalid pointer";
> > +       pr_alert("%s in range [0x%016lx-0x%016lx]\n", addr_type,
> > +                orig_addr, orig_addr + (1 << KASAN_SHADOW_SCALE_SHIFT) - 1);
>
> "(1 << KASAN_SHADOW_SCALE_SHIFT) - 1)" part may be replaced with
> KASAN_SHADOW_MASK.
> Overall it can make sense to move this mm/kasan/report.c b/c we are
> open-coding a number of things here (e.g. reverse address mapping). If
> another arch will do the same, it will need all of this code too (?).

Alright, I'll try to move it over.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez11Bhd%2B76T2L9xF64TZQOeezJ9%2B9GApG2A7eA1hVfG3eA%40mail.gmail.com.
