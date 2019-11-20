Return-Path: <kasan-dev+bncBD7LZ45K3ECBBM6M2TXAKGQEYFLQQPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B0391038D9
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 12:40:36 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id u14sf982454wrq.19
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 03:40:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574250035; cv=pass;
        d=google.com; s=arc-20160816;
        b=DlthCiyYk3Oo/Q0iOYJ4LuxlzPrSoFwEd40BB8avmXUDujwpH0y48w/N5tgJQPWETv
         rlbzD2fElqzCAjpzS6k1B4hJdteadggcZKfh6iReldGwJ8soYa6EEjG/ZaVFq1tEae8q
         eigD/xCPp6c7dfxth60NDEo4sIAnS4oh7t4jCBpQVVgEVGBO9kjpdyTP5aT08wRhqDr6
         /9UGJbWRAQhGlC27efdBmzN5XGvBjNc0Ot54dGyAb4loCYOylnO3/zYRQSIKMratZ0UR
         pp4zwin7RWK3S92dXdHp9vxLY7mY3UNIOGh6JmFh2jMGTr0jaNd6RLVyMoTi3ke453PQ
         ic7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=YjBXczKcAGlQ+T7XBBNz4uYP/fYdWB0Z0W0OUMc5THc=;
        b=Fq4txprKwcnRLRypjIdx7dSoa+8C6zbhEHQslxg8KmSKeHzSHVfN+/REoDZEQYzO6D
         EpFAmBxHmVkpCUobu31NNvp2SPHyFXJZB9Ns2AK6xYP8c9jujHppOJoIkJBUcQdbtlF+
         kTIiXmaQUHBh+F70/2+On6M88hMmkfSF124V6MM3Nw0R77OBFK70+lN/oVQsNPZQW1BL
         gIvTsl6CNsJ6RtExnpgk5yaPS11bN4v7rbJblKwOSstWYNxndvg4KbioZgQpysMvRzDG
         pmIxrYJFALvS8oiVGI8NJib2vAMWihnFAOffqTee+JFbTJEydZLw7fIMleuTrJO1btyz
         zmOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=EKkBQD69;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YjBXczKcAGlQ+T7XBBNz4uYP/fYdWB0Z0W0OUMc5THc=;
        b=XDkvWv4DQNIT6oH0THpNNqFsrX51DLirExPUHTXX6MKPG5Kp6eX5oD9uLPyVGHiDqp
         RjWiA2eI9jKpRkK8in/n3p7giBSG9R9sBiKyZiM6Sq2Ma+JC8fwYZvXFsRCgO9oknzLd
         TGxnUqL2BLjd6P3pBsJdRAknJOphHqktjmVnunBXx7nGXfxyk45Ewp24x2mQkEvV/u8A
         VPIKMnz+7OiQpE7KkxzXgVV72ubPXsLwZg9NzsLyVEZUiQBI5FBu8K0gd1Jkjh07oEs2
         9BHFRzn2DjhtxkXx43WMUwr7vH3ynaCCX2tbpsD67+jKupWMbmA4uWQD8I3S6x5biVgp
         qgTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YjBXczKcAGlQ+T7XBBNz4uYP/fYdWB0Z0W0OUMc5THc=;
        b=hxC1St4EKgWbYG0mG2z8jkjlWejMrmu9yT8qgs+tX0y2nMVcfawnythgAE9UeS5olA
         ksZ/2NXUztM3WmkjqIq74xnAKnZV1w6/cdIAWnqlDGjIMfHj6SM7VKstwOVX1Eu16gIB
         YIpx/dvFwEH77rRSCBMiOHhFQjFI6BjrK6WZsczHCDduzD7/RNGgv9zojq5n7RA4b/D+
         kdfh75JT5jz8ua24/fZvMUKgT60fpCi2V1kgk+oM2FvOb6q9BZ4ixzfSBDFu+g/eucej
         m6hmuRmHsh/D7Zj54+s2cRFjpLbAQKYDlJTQguXlhV8zFeCvdGDkz/EOrnUUYcdkqQt8
         zDSA==
X-Gm-Message-State: APjAAAX9fPuWsPRnFmityOnmG/8yVZ9LowoteFNXtTsKxZ15+h6C4b37
	Xd7jflFuH6pnXNyYR3RhdTY=
X-Google-Smtp-Source: APXvYqy8wuZlUG8Vgstk5lfVP4H13Zaa9LSiQtLSGZulKlJoMnGeYJxrxby84/s/N0YG2YyItvZZ/g==
X-Received: by 2002:adf:cc8e:: with SMTP id p14mr2612477wrj.172.1574250035854;
        Wed, 20 Nov 2019 03:40:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f10c:: with SMTP id r12ls677019wro.11.gmail; Wed, 20 Nov
 2019 03:40:35 -0800 (PST)
X-Received: by 2002:a5d:640d:: with SMTP id z13mr2909188wru.68.1574250035123;
        Wed, 20 Nov 2019 03:40:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574250035; cv=none;
        d=google.com; s=arc-20160816;
        b=QeocvBXOp/LYsrtNtZQZJtwGMSY5IPOnJrHo9vMq7rwVIEgYhGUp0Veoq1o6WloO/9
         v8rRAY7/ZP2X8ijXntuDaOaj+EoAZkshTZxepj/9bX97oNU9GPiAqFDGp/RmWMhvnKSO
         Jl36qz49jZDnJvudg97uCPSh25FXTc94hCY+S/yyGGt8xY1Hz2j7Ei3MV9/b1nqtGZY6
         pDHJE+42Aki0jIOYygVvnQjF117/UzySKWKImS7h+z1hiZxE2E1y9kgibYD9mg3nJPmT
         odQRQjF7k1pIwbHPVbeh0X37s8iEPSS7fLVIDprlYz4BJddtuIDmimlIRc0W0cvvGmz7
         7FjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=69RZrXkuGAApUnr4iO+YhE+hxS3D9Hh/3GfnGeQJbmc=;
        b=f5udk8i9rHgEWHkjPxEvRDGgBIz069ViU4Yb07kTFhiZ8h5+fs5wDQQ9UYnX/PU+lV
         JKOlF7gqgjEATSO1tWK8pKdQSquy7Yizn7h+qSeS2IO6jTEv9yKgSpHJzRZia7HtGo1i
         3bvsDuH5QGNAFOUlgqxpJ3h+6OFFg9mwhdLvQ+GK1Fz3yQVKm1Hx0iqPR+z4m/E0K8eB
         ticRjXJJD/5GCmBRUVgGCK/flEibARZ0iIDSE4YDWCTCvkBx06vb2tJaHhRzPw7I06ab
         t2uPKtOd2HEPLbfAVwqwRMRc25iZF0so+ajYsKkVvVt6lORUWLstG04XeRgbZTfde49I
         tjzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=EKkBQD69;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id h2si1295065wre.0.2019.11.20.03.40.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 03:40:35 -0800 (PST)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id z10so27737845wrs.12
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 03:40:35 -0800 (PST)
X-Received: by 2002:a5d:66cf:: with SMTP id k15mr2692723wrw.38.1574250034732;
        Wed, 20 Nov 2019 03:40:34 -0800 (PST)
Received: from gmail.com (54033286.catv.pool.telekom.hu. [84.3.50.134])
        by smtp.gmail.com with ESMTPSA id s11sm30289635wrr.43.2019.11.20.03.40.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Nov 2019 03:40:34 -0800 (PST)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Wed, 20 Nov 2019 12:40:31 +0100
From: Ingo Molnar <mingo@kernel.org>
To: Borislav Petkov <bp@alien8.de>
Cc: Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120114031.GA83574@gmail.com>
References: <20191115191728.87338-1-jannh@google.com>
 <20191115191728.87338-2-jannh@google.com>
 <20191118142144.GC6363@zn.tnic>
 <CACT4Y+bCOr=du1QEg8TtiZ-X6U+8ZPR4N07rJOeSCsd5h+zO3w@mail.gmail.com>
 <CAG48ez1AWW7FkvU31ahy=0ZiaAreSMz=FFA0u8-XkXT9hNdWKA@mail.gmail.com>
 <CACT4Y+bfF86YY_zEGWO1sK0NwuYgr8Cx0wFewRDq0WL_GBgO0Q@mail.gmail.com>
 <20191118164407.GH6363@zn.tnic>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191118164407.GH6363@zn.tnic>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=EKkBQD69;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Borislav Petkov <bp@alien8.de> wrote:

> On Mon, Nov 18, 2019 at 05:29:42PM +0100, Dmitry Vyukov wrote:
> > > And of not having a standard way to signal "this line starts something
> > > that should be reported as a bug"? Maybe as a longer-term idea, it'd
> > > help to have some sort of extra prefix byte that the kernel can print
> > > to say "here comes a bug report, first line should be the subject", or
> > > something like that, similar to how we have loglevels...
> > 
> > This would be great.
> > Also a way to denote crash end.
> > However we have lots of special logic for subjects, not sure if kernel
> > could provide good subject:
> > https://github.com/google/syzkaller/blob/1daed50ac33511e1a107228a9c3b80e5c4aebb5c/pkg/report/linux.go#L537-L1588
> > Probably it could, but it won't be completely trivial. E.g. if there
> > is a stall inside of a timer function, it should give the name of the
> > actual timer callback as identity ("stall in timer_subsystem_foo"). Or
> > for syscalls we use more disambiguation b/c "in sys_ioclt" is not much
> > different than saying "there is a bug in kernel" :)
> 
> While external tools are fine and cool, they can't really block kernel
> development and printk strings format is not an ABI. And yeah, we have
> this discussion each time someone proposes changes to those "magic"
> strings but I guess it is about time to fix this in a way that any
> future changes don't break tools.
> 
> And so I like the idea of marking *only* the first splat with some small
> prefix char as that first splat is the special and very important one.
> I.e., the one where die_counter is 0.
> 
> So I could very well imagine something like:
> 
> ...
> [    2.523708] Write protecting the kernel read-only data: 16384k
> [    2.524729] Freeing unused kernel image (text/rodata gap) memory: 2040K
> [    2.525594] Freeing unused kernel image (rodata/data gap) memory: 368K
> [    2.541414] x86/mm: Checked W+X mappings: passed, no W+X pages found.
> 
> <--- important first splat starts here:
> 
> [    2.542218] [*] general protection fault while derefing a non-canonical address 0xdfff000000000001: 0000 [#1] PREEMPT SMP
> [    2.543343] [*] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.4.0-rc8+ #8
> [    2.544138] [*] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.1-1 04/01/2014
> [    2.545120] [*] RIP: 0010:kernel_init+0x58/0x107
> [    2.546055] [*] Code: 48 c7 c7 e0 5c e7 81 e8 eb d2 90 ff c7 05 77 d6 95 00 02 00 00 00 e8 4e 1d a2 ff e8 69 b7 91 ff 48 b8 01 00 00 00 00 00 ff df <ff> e0 48 8b 3d fe 54 d7 00 48 85 ff 74 22 e8 76 93 84 ff 85 c0 89

> <--- and ends here.
> 
> to denote that first splat. And the '*' thing is just an example - it
> can be any char - whatever's easier to grep for.

Well, this would break various pieces of tooling I'm sure.

Maybe it would be nicer to tooling to embedd the splat-counter in the 
timestamp in a way:

> [    2.542218-#1] general protection fault while derefing a non-canonical address 0xdfff000000000001: 0000 [#1] PREEMPT SMP
> [    2.543343-#1] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.4.0-rc8+ #8
> [    2.544138-#1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.1-1 04/01/2014
> [    2.545120-#1] RIP: 0010:kernel_init+0x58/0x107
> [    2.546055-#1] Code: 48 c7 c7 e0 5c e7 81 e8 eb d2 90 ff c7 05 77 d6 95 00 02 00 00 00 e8 4e 1d a2 ff e8 69 b7 91 ff 48 b8 01 00 00 00 00 00 ff df <ff> e0 48 8b 3d fe 54 d7 00 48 85 ff 74 22 e8 76 93 84 ff 85 c0 89

That way we'd not only know that it's the first splat, but we'd know it 
from all the *other* splats as well where they are in the splat-rank ;-)

(Also Cc:-ed Linus.)

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120114031.GA83574%40gmail.com.
