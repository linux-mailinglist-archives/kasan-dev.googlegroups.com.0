Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBSMH5DFAMGQES25RKIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id C2BB4CF0A46
	for <lists+kasan-dev@lfdr.de>; Sun, 04 Jan 2026 07:08:10 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-430f5dcd4d3sf539426f8f.1
        for <lists+kasan-dev@lfdr.de>; Sat, 03 Jan 2026 22:08:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767506890; cv=pass;
        d=google.com; s=arc-20240605;
        b=V66OKMNKBo0I1oJhlmeUy0m9cdphmzUZ7MJfyE9u9DykGdX6479edEjLhQt2+GAIlF
         V6QMHK9J1A4yeYSucV+wzfi6b8AAlRcVsDezLS4KubVhi41RJfFcaYP3HK85CgIfjy8j
         Rktrj/oS4pQaTk+uIvA96c8TzI+YfbPd69spVYOm/mpnqSf5hoqZ6TGyFD5F8QIJvjnP
         c4NtSV/vEEIL8KbINIbX66nP/tCeCCtKVMD18FF4yENGcgNQskOjKR7RN75bKQuel+tV
         dDD1HHDt9OS52+Kg07AKm0VMVwOW/2HMzU8vq5gN20mLIyWW395Ap9xGH/tF0qu09SOj
         8Xiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bNePgP4zRm8nJ0wo6dwTeO1UvRHMZfKpwIaLbaqRhlQ=;
        fh=9whkvM/Kv7x4NNfF6ksuD2xF9uzsnQxM1pfWz5O40Gw=;
        b=TC0GufMixeBUTmg1DUulHMIaNabnXJoKvjBxnSKv4j1YbVFGjlG26uXOjCsBdqBHBP
         Jk3Tf5vO4H9NKD6uPN5t+lbpGohxjCZCJeS0bb7dQvktIvXJvCUYJza9dHdqvxFGoTss
         lWXubUoWB7FPn9o2jX+4dMwzhwgujhPVE8KO/lfN0JpaCBJsfgMytZ6uN3QObjBPASk5
         aZ9GsVezBRUGgA7C4G+CVZAP9+1sS/bK+CmMcFBM+KbLbzUHYKX+G/gd8DSiAZ1KqEa9
         fKCQ1lpZdf6YfbojT3tKLUIIO8OEdrO8EcySSAmNpKDiB7RU9yoRGenMZdDSDEPNIIdX
         qe3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=enMAZiVR;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767506890; x=1768111690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bNePgP4zRm8nJ0wo6dwTeO1UvRHMZfKpwIaLbaqRhlQ=;
        b=I0Ez0N56RQZAdSyAGjpAMYBqdw8kplC/0OTYItD7n7FC0aTeSMVNxexxk4sYDn1fzd
         tE0SzHFHq+fKzTnGh/IeI58ikhmYRKMQqAPbyemLdX3m+WVDKonrvABinSDft/OZcOjF
         jSJPBZaLponjbRxNOcanEGKSgcZn9TQEZntC2fgU+xo0w19TgzZMkY7/Pa7xK3BzkZvY
         kIsszVxne1g9YFw8kAEdBhA2ngHSM9Rv2EzqTSY+vEHu1YPMVH6GbeXYf9z7EFlXyORF
         E9qw4PiUuksaG0zLUKDdVX+QoDGPfYewtktSQ2X+41bLXrG6gYddMfvt6NkUkB6UneE1
         ZwbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767506890; x=1768111690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bNePgP4zRm8nJ0wo6dwTeO1UvRHMZfKpwIaLbaqRhlQ=;
        b=njDtxxmacb1SBUT8ktYDTrp0uaw5Ydn7nNXp8+YpuU5laIRanU/QuDlptxWhz0QeiZ
         QXrZ/W6PRknQ9x14qtCwCRVYcZy47JU2mkE6t11HdIiMfmtFDthGBonZ269aACfO2VRf
         utQza1B5h9F1Oy6UoPuUhxip4Iy+xKCIFV5kxKT2QB4+Dgk/o44+wculAvb0VnpPsHHS
         5edVks327tGhjp96+35doijimVr6b3ttqB/6iHeZOhiHa4q8NZ0xOE3ZTp8ByMOQVPGN
         2jsvvN2yH8L2TvvYupmQB1Cn6evDiMLRS6almBxJs6rdb4yYWKdp7a7iwMr0tttPNoys
         8QfA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXu3GueeLqrwtBJ0WiRgFfBRQ5TbtA7g/5z3gaLHW0cItfYuEYe9SL1P2zMBycHzXb1oFo8CA==@lfdr.de
X-Gm-Message-State: AOJu0YyRZ1GdW7MVkPrMPnDoyW366Kmwl3EVGFp+V1ei1Kx/hHxu6FFP
	/f6sGBYxP6T2Zo/rLG3ELYYEsnAN9emxT6gGMy0s2t1AIaRinEZBAOPI
X-Google-Smtp-Source: AGHT+IGZUtpN+Wz3kzvjv6j8RD9T+pruBb35urN6dlgANs9PGleEeZNKbG2C8LarAdkzhE4+vL7bug==
X-Received: by 2002:a05:6000:2284:b0:432:5b18:2cc3 with SMTP id ffacd0b85a97d-432aa3e9b9emr5937561f8f.4.1767506889858;
        Sat, 03 Jan 2026 22:08:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZH4RzHXQEgWmB0N5FchhKswcEDWyqFz3gY97E4xI+lbQ=="
Received: by 2002:a05:6000:400e:b0:42b:2f75:332 with SMTP id
 ffacd0b85a97d-432aa20309fls511117f8f.0.-pod-prod-00-eu; Sat, 03 Jan 2026
 22:08:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUTz6sGgHmbNzX9PowGyH7X3R0i5vwEuVkr1nm1wDJdh+3fPff5d02qGWrEov3sb1Er8AGv9xqQFhg=@googlegroups.com
X-Received: by 2002:a05:6000:26c5:b0:432:84f0:9683 with SMTP id ffacd0b85a97d-432aa42cd08mr5785285f8f.24.1767506887541;
        Sat, 03 Jan 2026 22:08:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767506887; cv=none;
        d=google.com; s=arc-20240605;
        b=YPw0l23EzdXcXfHbd/DX3fI41jEUo1qu1A8AwgsrHeh8sGT8DEv9k2QmVs8rB18STj
         aiX0/uLQTOmtfN8KbT0TlkxFMGpc7TZsYQZbVPSETluyF+NLS1OYQtC+3fB8tUqL05rc
         +I4oPq9KEbZM4/G8r84VIhPJUqmGzB/nKl8vAPPfwuVTllVrGPqJACAyLpR0CC85XETC
         don52bS+FugJ6qikndh3eNnJ3aZgBHWaYSZXiER2tln6N5whgoGseJHs2KJlHxNqvy3f
         o2E7LwEJHKRMY7aSftYAP/IYP34XY9aXY/t4sW3PznMBVjUlQJFS+DR2qCLs9xv54Kf0
         I3Wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Dbqd0rL3/FzIbYne0vhVXhUp0QRkV7TNMnop++/0n8U=;
        fh=J80QemNALQ9Ailtfs2QdDdqyRE68ult94dIVHw71AoA=;
        b=EJV1xWBWPoTUgck2TF2/5y07lhr74nKfgbcdFwMTmGwTc7fiJVavMB+z3ZPBfLjC8M
         isNmDDPxbjeV7S9EQOGWhJ+hj+mqd+2H24aze+8Ki4SYD5rWMgyBjCGUUUzeSVy7GGbL
         joaMau9rqXLfpHvOgDhtaZXLIBgJ15P4Bamb41Kku3HvHQbKP7ir1YXQq9YxJ9dfHb2v
         Uzzjmp8ZCJATYDV6BueogQwK8rsP9uBRvyfna0HGxRMZvLslDgluELCF8+izt2EC+aWq
         qWXk6YgloZOBp1n8YzBQ1WOf4/ATMaLL2dx7zC5b/9tPMzDqc0xhoFPW6Klln1wgCAyW
         kJZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=enMAZiVR;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [2a01:4f9:3051:3f93::2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432650f05a5si509453f8f.2.2026.01.03.22.08.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 03 Jan 2026 22:08:07 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) client-ip=2a01:4f9:3051:3f93::2;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 5DCB840E0200;
	Sun,  4 Jan 2026 06:08:06 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id 1BXU3Dj6OJrw; Sun,  4 Jan 2026 06:08:02 +0000 (UTC)
Received: from zn.tnic (pd953023b.dip0.t-ipconnect.de [217.83.2.59])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with UTF8SMTPSA id 4107B40E01B0;
	Sun,  4 Jan 2026 06:07:40 +0000 (UTC)
Date: Sun, 4 Jan 2026 07:07:39 +0100
From: Borislav Petkov <bp@alien8.de>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Brendan Jackman <jackmanb@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>, Ard Biesheuvel <ardb@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH v3 1/3] kasan: mark !__SANITIZE_ADDRESS__ stubs
 __always_inline
Message-ID: <20260104060739.GAaVoDq_VggsNP5jif@fat_crate.local>
References: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
 <20251216-gcov-inline-noinstr-v3-1-10244d154451@google.com>
 <20251216130155.GD3707891@noisy.programming.kicks-ass.net>
 <DF0JIYFQGFCP.9RDI8V58PFNH@google.com>
 <20251218092439.GL3707891@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251218092439.GL3707891@noisy.programming.kicks-ass.net>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=enMAZiVR;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Thu, Dec 18, 2025 at 10:24:39AM +0100, Peter Zijlstra wrote:
> > And in the meantime, I guess patch 3/3 is OK? 
> 
> I'm not sure, ISTR having yelled profanities at GCOV in general for
> being just straight up broken. And people seem to insist on adding more
> and more *COV variants and I keep yelling at them or something.
> 
> That is GCOV, KCOV and llvm-cov are all doing basically the same damn
> thing (and sure, llvm-cov gets more edges but details) and we should not
> be having 3 different damn interfaces for it. Also, they all should
> bloody well respect noinstr and if they don't they're just broken and
> all that :-)
> 
> That is, I'd as soon just make them all "depend BROKEN" and call it a
> day.

Right.

And I don't think anyone has had any serious plans for COV-ing the SEV code so
lemme take 3/3.

I, like Peter, am gravitating towards a kill-that-thing-with-a-master-switch
instead of whack-a-mole-ing the kernel.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260104060739.GAaVoDq_VggsNP5jif%40fat_crate.local.
