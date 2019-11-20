Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBLMZ2XXAKGQEBIVXG5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3a.google.com (mail-yw1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A162103D3A
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 15:24:47 +0100 (CET)
Received: by mail-yw1-xc3a.google.com with SMTP id t19sf17835060ywf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 06:24:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574259886; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ng/gahxsUqxAxY4GGFP9jmTxESIc2dac5su6KSPJ2Atd/wQyGASWcdsvK8hI85j+PW
         tlIYvCw56Je2ypFf7Ic5ACDTJZYNlA+HY1p1E82PRI+2sICC0LrGvLlw1BJTpo4LIPhK
         5DOnAOX/dWCWB5Yg4Tws+LDpS18sRX1clH+Wf6Ne9W43YNZLjY24OYKfq4q2vodVm1pQ
         cycZ1phSRkq94x1IhjwRkvRVnmwj+RIQu4kX5bhwYN/psyjgyOrzHHkhXlE61Wbgm2xM
         uszJipb/Sc8s7B4hVMHO4iJgMXnapaCvPokJZaiK2Yo+jYawXGJgo5ebubjAI0Mua8Nk
         +WjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=O873Mhq2AMemsUyKMFC4KwU9CWxU61xh3hvrYRltIik=;
        b=f5sSNiajE/rIBmuiLl3SW74cMkAo523zsqzBF/fvuH5kPOWIImAWUHtmE5eA5s9xrn
         5qWNACvAUoT5PRTgt6WnytLKKLFYUbI8DzDT8KQQoxFkR+qBHS3sUuXrPO4Zveg30ylT
         Crwfg92bfNJyb7YOmaIzS8xAOK9H16F8wobWjghDkx42GTIJVFbTLYwHLAitpNFP+dVj
         E0cmKeVQGeL3d7GTMpV9pgy7Q3ZNWJmvP0mIRCeZoVg/PnSL8BeVZzb5vTgKB7BmXTMN
         CDg9qQ8K3BemAm6Z+1/2O65ZzJvFKs4Sig2DLHYKf9OngPsrnNogLb/RuOgE4u+9QLFW
         wmtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k0ZQSWb3;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O873Mhq2AMemsUyKMFC4KwU9CWxU61xh3hvrYRltIik=;
        b=Sy4y4tfhxztm3o7FketpPhFYxJHQMh/ErOQGuqmp+MxHTHMkkFZXadQvUk/XoHRAv9
         0noTAiMMfV93gwaKgmOQX8WURHqfoB3OAd0ehgW33VldCaI/xBVaPxd4dUzdt9RetLif
         KewbP2k99+GMjBxOt2DuOS5ORuKetivnb3gnCZNUNweMtCmJEtmqzWq0+tD37108EuuQ
         x6tIVGsfcdKTkLRjSltEYW0fHhg3vBhHkL46PrFkw7DAP+jvqN7j4Nyx38fnhHZ+gLFq
         AZx005l21kp9i0LfNhkQsUeMjeZ9h9px6sML7mX4cg3xB+v857LHsPBtfksEsmIMYXRs
         UYcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O873Mhq2AMemsUyKMFC4KwU9CWxU61xh3hvrYRltIik=;
        b=Jqykl31eRX4wkIpX+SEHbp/+LMGCRPDXBFViMPmPQwHNbKYdSAtuKRsBMvx+jyUtgv
         8TyAYGsT45ErbCfiiHVGEmyHBD0MI5qCpiL70N8iXEnHAKHHS3W82uGaPuEi2Hve2Zzd
         j2hXG9IMBkQ+jHmCa7mD1oK7xvBKZtujRIyGnA92w6T4fRQ5wqCROWCE5/pOiIKZgh/V
         1dUM4hZ/8Jgu/2iDUZ0pkA6XrqzxNcwTo9op5i3VugjHsq6ZvXoNmaxD6T/BudsEHDKI
         //AjZ4tWy2M1ty2Z6SjGqJ4ZtdW4xH8d7LK8dIB64yeX+BOZOGa4iUcvfwOTWEtOhEEy
         EF2w==
X-Gm-Message-State: APjAAAUV/yLvnXaZkqRY5+wbLn68d+qluFWHTg84E2J2Ys/LQ1/icnfd
	fAZgA7OLrtd5gdvgIETfkqI=
X-Google-Smtp-Source: APXvYqzNtBXxxUQIDyC6jM4SXeDTMo6j1wl6dTswZ4gOth27vO1YVYJkJ5Xl0kruLhzBDHzUcCisJw==
X-Received: by 2002:a0d:db04:: with SMTP id d4mr1825467ywe.320.1574259886104;
        Wed, 20 Nov 2019 06:24:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:3dc7:: with SMTP id k190ls269623ywa.8.gmail; Wed, 20 Nov
 2019 06:24:45 -0800 (PST)
X-Received: by 2002:a81:30cd:: with SMTP id w196mr1857910yww.204.1574259885647;
        Wed, 20 Nov 2019 06:24:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574259885; cv=none;
        d=google.com; s=arc-20160816;
        b=c7RdTlrvK5GhkRharCuIFNLOJ7CQQg5+5i9lfsSInmRkBGckSxh9jY6gBd/e5kdhjI
         KpoAbt62ANfiljnlRzPOIIeN6GaATt4UpGuVGzmSNgKtkN8d2T00W1psLEJq3Y9b+Fan
         g8cL8vmkrfPRnAjaPY0P8UWKiEnXKSWhncCtWVREa5pHuAJZ2RqxQ8BGRbnC8f5hqCLw
         7UkkyT2zn6q9XpOSQaPILP2GzJ1qpvXnQxWjvzjIUn25HI4fq7TCS+G1V3PO8Oe5zKtR
         O2oKtHBY+t5QVZqXe/BmZrWydBpFdTucGH9fJ35AEfjV4TcIRO+igTvgehhPa/0UftXI
         bGHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yOFfvevSyIuI2uXnhKhqs1DyN3AcbeT8ZG1uPgE2BRM=;
        b=mV/V2nsWbJrmGRX8jNmFRDdvTYybDNLOONNNGwEPRqnoW45vfYvKHD8Nkfc67OewPt
         9D7tnmMlVo+XLvliImr3v2jZcktKApi4q63zQ3VFp0WUCcCdTlwfzaW0pAyd6n2L8gWz
         ztW48Pd8e0GIkn4q3DbZbeLhVSTiNmoVbA1yt//sx4uwHwRV9H7oNOdtHaIwkw2RBEbd
         kLhWOqlzXYGSmhWu6d3gOJ7flTPqnRJ8HR4cgdBoElGXU5ZklbMKyHR0jrfFg8L2Po8l
         vDWUDT11+v/Zipl7wEffXO3WTCqk44KrOqZCp/s6W2pWRO40bp2ffCBr676TihF9B0jp
         TxMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k0ZQSWb3;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id u3si1443991ywf.4.2019.11.20.06.24.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 06:24:45 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id l14so21304317oti.10
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 06:24:45 -0800 (PST)
X-Received: by 2002:a9d:328:: with SMTP id 37mr2126736otv.228.1574259884942;
 Wed, 20 Nov 2019 06:24:44 -0800 (PST)
MIME-Version: 1.0
References: <20191115191728.87338-1-jannh@google.com> <20191115191728.87338-2-jannh@google.com>
 <87lfsbfa2q.fsf@linux.intel.com> <CAG48ez2QFz9zEQ65VTc0uGB=s3uwkegR=nrH6+yoW-j4ymtq7Q@mail.gmail.com>
 <20191120135607.GA84886@tassilo.jf.intel.com>
In-Reply-To: <20191120135607.GA84886@tassilo.jf.intel.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Nov 2019 15:24:17 +0100
Message-ID: <CAG48ez11aL5OsDCTF=E6h=_DF6ojmunwp1BcWL73EsQLrmsttQ@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
To: Andi Kleen <ak@linux.intel.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel list <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=k0ZQSWb3;       spf=pass
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

On Wed, Nov 20, 2019 at 2:56 PM Andi Kleen <ak@linux.intel.com> wrote:
> > Is there a specific concern you have about the instruction decoder? As
> > far as I can tell, all the paths of insn_get_addr_ref() only work if
> > the instruction has a mod R/M byte according to the instruction
> > tables, and then figures out the address based on that. While that
> > means that there's a wide variety of cases in which we won't be able
> > to figure out the address, I'm not aware of anything specific that is
> > likely to lead to false positives.
>
> First there will be a lot of cases you'll just print 0, even
> though 0 is canonical if there is no operand.

Why would I print zeroes if there is no operand? The decoder logic
returns a -1 if it can't find a mod r/m byte, which causes the #GP
handler to not print any address at all. Or are you talking about some
weird instruction that takes an operand that is actually ignored, or
something weird like that?

> Then it might be that the address is canonical, but triggers
> #GP anyways (e.g. unaligned SSE)

Which is an argument for printing the address even if it is canonical,
as Ingo suggested, I guess.

> Or it might be the wrong address if there is an operand,
> there are many complex instructions that reference something
> in memory, and usually do canonical checking there.

In which case you'd probably usually see a canonical address in the
instruction's argument, which causes the error message to not appear
(in patch v2/v3) / to be different (in my current draft for patch v4).
And as Ingo said over in the other thread, even if the argument is not
directly the faulting address at all, it might still help with
figuring out what's going on.

> And some other odd cases. For example when the instruction length
> exceeds 15 bytes.

But this is the #GP handler. Don't overlong instructions give you #UD instead?

> I know there is fuzzing for the instruction
> decoder, but it might be worth double checking it handles
> all of that correctly. I'm not sure how good the fuzzer's coverage
> is.
>
> At a minimum you should probably check if the address is
> actually non canonical. Maybe that's simple enough and weeds out
> most cases.

The patch you're commenting on does that already; quoting the patch:

+       /* Bail out if insn_get_addr_ref() failed or we got a kernel address. */
+       if (addr_ref >= ~__VIRTUAL_MASK)
+               return;
+
+       /* Bail out if the entire operand is in the canonical user half. */
+       if (addr_ref + insn.opnd_bytes - 1 <= __VIRTUAL_MASK)
+               return;

But at Ingo's request, I'm planning to change that in the v4 patch;
see <https://lore.kernel.org/lkml/20191120111859.GA115930@gmail.com/>
and <https://lore.kernel.org/lkml/CAG48ez0Frp4-+xHZ=UhbHh0hC_h-1VtJfwHw=kDo6NahyMv1ig@mail.gmail.com/>.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez11aL5OsDCTF%3DE6h%3D_DF6ojmunwp1BcWL73EsQLrmsttQ%40mail.gmail.com.
