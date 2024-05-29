Return-Path: <kasan-dev+bncBDZIZ2OL6IIRBG7C3WZAMGQEDW6UGRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 377EF8D3E30
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 20:17:01 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3737b3ae019sf25093215ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 11:17:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717006620; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tnrthy7xg/2aO89dRXSsbznuspW7+qTiJOfse8KtON3jO9UtJIqEMtqJ2fAr/WmsE+
         FpoqtnwoB9ie2fkUXIwm8dP4rblT9+xtJvoSyPmEj1+llD2EB1ja6bAl3zVURlOZsvf7
         867n6Nf9Oy9svb05DoyFoJ1oDpBluFU+IIOQU/ETV97CjGTSrM0rMMIn4QlVlhSDoAza
         knvnLdR7k5qwHi6wGdxay/EzdbHegczgjixds/alWY3uBYNY9HGapmBuU1MiR9Tds5u8
         KhCImGLDytrHTIyvl9sfoXX+wV9fmzVv+5wcs2jCMwKFZcRxI2wumwE/5ilBpGISlYzn
         ayhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=Z1MwKzpGc6mi7MvLlHbsbjck7+IRDra2Scg/rYIhO+U=;
        fh=H8LFjL/qRWKOkXrzthPwpmrGjF6j09FIc6uSJOh392M=;
        b=shNDcDrQpdENcuBf5/Rhww8PQOZPzP0V/dP2TCVe2ArxVlvNACzj4pchkret2ZHzph
         HY6FjSHdyjWM3pyzoqthYVQaDh98lvp+FKLw0aLlv7BqS7E2RdgRRtzHZx5OO+hhKNzL
         pNkR2D7cL7GU4tt06FbQgwY0JokPnMRXXWF7IiMh5LkFJVev7h4Reh86TYmGxYdWRqtn
         K6dPIYfMW1cydp94/qKav5UihR7U0/xoVIwKVOn5zaKu6h1DXNaNyeWgc9vkNQiZGbw7
         kTx9bq9db4HfTBzur4Nqmh4XIob0OIzg7B4glUzG7IcHySuG9FSiauzOeO+/C6nk0QAx
         dd3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nH4RTV8W;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717006620; x=1717611420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Z1MwKzpGc6mi7MvLlHbsbjck7+IRDra2Scg/rYIhO+U=;
        b=GJcMcJsO89zygUcJxtf8VQLPNEnz4k0mZImuUF6ngpiAWUxJ+99MhdqL6RrNwJjvX3
         Yt1PaJ65MdppQwPisNeZePut1/muNKy+cDVNmnmexsTcykj0qqsefZn1waW99zvf5+BF
         qripq2ViWnDWu249foFPegiLYK0wtJ5m9nhQA3WK+D4PaGcwGoLu3xlnNeg6gYld9hJz
         ZYTDk7kbxyxRcXit8fOqUKt8HggI6Vi4NT7JyQO09GiRopF8hpJWsndmDBUi1rz3E4eA
         rIkLIZ7OIxX/FeKtws5Bebuiko+i5cE0j+qT32/72eWKxQV9kJx4wRhFz4PSBcsmRjkd
         g8jA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1717006620; x=1717611420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Z1MwKzpGc6mi7MvLlHbsbjck7+IRDra2Scg/rYIhO+U=;
        b=d22bfg1Wl1EiLJx/EGwZa/l6bZ+9t7eqCYhhtv4UUm0gbRO4YjXjsDyMvKgOE97oVL
         Wx41JGQzFMwtPcufRbHKoezcIRUE+lRbGEC1atsdpGTmkmCl3FPQsC8+OvytT2euz2Hb
         ZmMZYUvR/DEqGXj1R13bASOm2tTXInI7w2TpIgSGEbJASjtP6JFNhCTEjHwfmeCHxnfp
         0ibv2zr41WqzKVqhhRa9xIFWPYDU4ltwHPfLBdRO0dJwRspC5UbV8qh+Bym8AXSTOnBl
         aL/TJdDuUkJKzaXcRxVEYiqeBFIXoIiZTdEnAKwToFC4uZ5FFTsUYzSyGdhwbSHOV69j
         cpaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717006620; x=1717611420;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Z1MwKzpGc6mi7MvLlHbsbjck7+IRDra2Scg/rYIhO+U=;
        b=SL6OXHqZ9apYoSLhNPOAM3N2cNsys/e3cu6cgQeJPai6r4+T2bbLydyQmnF+JuU8KQ
         /OPvrQARQZyJACbRGUKeXiJI+UWTjcvOf6+zBba9di70tM1hQRxv46tO4WPseVHoOvoC
         hKEY32e4QTZLkjPvPoz8+EXBgisOnzSOHkT+F09VidQN+HK1WOk2SONRHxpUeVBpGrxZ
         QPxvErtNj1cb9i28vqYAmFSuywJJE7aER/nJQTYc0trHDDRcNdHK1qPaFZ4hLWKLmgN4
         iSDs4uaZPLnp+7r0utGsrw2fDQ56J9hBdIrOREE7XCqYVBNILcY8rBJoIWC4zcoMqrIX
         9PUg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV3ZfIt0uZF3Oodc9t62zhEianjyXDk1YwKLFo48h6boEA5iYLhPZOyHv0BGe4bhTKw3rTAlHIcgivg+YmmbyNBdTSpyHlr7w==
X-Gm-Message-State: AOJu0YyR13AnPWYakdsuVj/YrUQgAdeFNTE8nPpdYedWpXPgLBg9w2Oj
	IPI8OzTcPQTUsUk7G85VihCxso0rz3eqjHLc5jaz8wlW0pA99wTP
X-Google-Smtp-Source: AGHT+IHIAPJhLqUS8SaXNKeHAuix/0fQIbWXN+5B1SoOtIuXjCDorrIClnbcUIDVPLExIO3+4W1hlw==
X-Received: by 2002:a05:6e02:13af:b0:36d:b8cd:7c76 with SMTP id e9e14a558f8ab-3737b2e1f59mr179732105ab.8.1717006619769;
        Wed, 29 May 2024 11:16:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cdae:0:b0:374:5315:95e6 with SMTP id e9e14a558f8ab-3747ab1587els722615ab.0.-pod-prod-04-us;
 Wed, 29 May 2024 11:16:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7DFYm1EE2VTY7tAT46/3Ve2eW227/I1za912OGFAVTPfAO7iwaawINkAmBZ1aGfmkyLM7xJ18I+HIOz+brwwKmypQjuekY39l3Q==
X-Received: by 2002:a05:6e02:1848:b0:36c:4d7d:26c2 with SMTP id e9e14a558f8ab-3737b3605f4mr169867035ab.22.1717006618128;
        Wed, 29 May 2024 11:16:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717006618; cv=none;
        d=google.com; s=arc-20160816;
        b=tF14FNHwd1k8OAiVUtPrpmBmMkGFmQ4Mr06xJ1WACNI1PQVV44yQMvfEqzOceOyTK0
         51vOqd9hE/nFCD2Wblb8XoUoWfN2TMm0n6hcXZQso6ioW8LOc2m/wDQRX1wS1O9G2+1U
         NcSd4qmRt8sbD65ahXTSvAc9fllaGBsBZ/T/wG6Ya2rsdM62VJynOE+hapQWrgsOHHfT
         2CZudz4Gw0P1l/lXFe+BUmUyrfVVY26Qm7mteH4/SoVSz93twUvcnrT3u//YJuHTUoHt
         R8n+2WqOSXhPj3RZ4msbUwLW7OWeCAkJLhxo8Gy8H7FuJ3qcFAHbYIpEJ8EOJNbeW/kK
         AHZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iXEkR867jEs+moBzGXY8ULu3YeFsr12ik86Lu88hpJM=;
        fh=eHexwptM/yeonLzYcc7C/9T2yd+OXYMWIMJ9H4q8bBY=;
        b=zRBh+NPvfndMLZkBW/swuTgA+jd61AzgrIbZlwwC3PvSbNGUD+ujLQnVyjEgy8i+xE
         H+0gnksJsbF3/3bWqmr2Wp2S1sBZ7gsNif642XIOC/5llKwN8QqhCRhTzCClWhmtWXmz
         RaqfhdrRPnezozwW/0L6B3pxpP2pNw1jFMbEl56FEqRuIZfWY9C4nTf+N+Ne5UtZ7dXx
         eAsvvBUaW+Ng6mrks1RzhycztETWRNhaNDbTGtKpBpiIkd0OYFyQgTMBkmRZSuiOSgZx
         a9KigQgxQ7JUunAzakLNwgmV7dXi/6trJTZpB8NEogjiyorujzc1dcXkDDEsGPPD5kHX
         QeiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nH4RTV8W;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-794abd3bfc6si55770185a.4.2024.05.29.11.16.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 May 2024 11:16:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id d9443c01a7336-1f32a3b9491so405785ad.0
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2024 11:16:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVybdXtzPNmxk0S4+cI8ZseMvTQ6DkYk4KuxC7kfKdrftZeCGjaoEdNlYJMkJM6yey6mgc8vFa633LPJmC6W07uHYERYIH8FSnOgg==
X-Received: by 2002:a17:902:dacc:b0:1f4:be9b:d306 with SMTP id d9443c01a7336-1f4be9bd71dmr75508835ad.31.1717006616911;
        Wed, 29 May 2024 11:16:56 -0700 (PDT)
Received: from Gatlins-MacBook-Pro.local ([131.252.142.255])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f44c7592e6sm102718815ad.45.2024.05.29.11.16.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 May 2024 11:16:56 -0700 (PDT)
Date: Wed, 29 May 2024 11:16:55 -0700
From: Gatlin Newhouse <gatlin.newhouse@gmail.com>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Kees Cook <keescook@chromium.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Baoquan He <bhe@redhat.com>, 
	Rick Edgecombe <rick.p.edgecombe@intel.com>, Changbin Du <changbin.du@huawei.com>, 
	Pengfei Xu <pengfei.xu@intel.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>, 
	Jason Gunthorpe <jgg@ziepe.ca>, "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, 
	llvm@lists.linux.dev
Subject: Re: [PATCH] x86/traps: Enable UBSAN traps on x86
Message-ID: <2j6nkzn2tfdwdqhoal5o56ds2hqg2sqk5diolv23l5nzteypzh@fi53ovwjjl3w>
References: <20240529022043.3661757-1-gatlin.newhouse@gmail.com>
 <CANpmjNM2S2whk31nfNGSBO5MFPPUHX7FPuHBJn1nN9zdP63xTw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM2S2whk31nfNGSBO5MFPPUHX7FPuHBJn1nN9zdP63xTw@mail.gmail.com>
X-Original-Sender: gatlin.newhouse@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nH4RTV8W;       spf=pass
 (google.com: domain of gatlin.newhouse@gmail.com designates
 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, May 29, 2024 at 09:25:21AM UTC, Marco Elver wrote:
> On Wed, 29 May 2024 at 04:20, Gatlin Newhouse <gatlin.newhouse@gmail.com> wrote:
> [...]
> >         if (regs->flags & X86_EFLAGS_IF)
> >                 raw_local_irq_enable();
> > -       if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> > -           handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> > -               regs->ip += LEN_UD2;
> > -               handled = true;
> > +
> > +       if (insn == INSN_UD2) {
> > +               if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> > +               handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> > +                       regs->ip += LEN_UD2;
> > +                       handled = true;
> > +               }
> > +       } else {
> > +               if (handle_ubsan_failure(regs, insn) == BUG_TRAP_TYPE_WARN) {
> 
> handle_ubsan_failure currently only returns BUG_TRAP_TYPE_NONE?
> 
> > +                       if (insn == INSN_REX)
> > +                               regs->ip += LEN_REX;
> > +                       regs->ip += LEN_UD1;
> > +                       handled = true;
> > +               }
> >         }
> >         if (regs->flags & X86_EFLAGS_IF)
> >                 raw_local_irq_disable();
> > diff --git a/arch/x86/kernel/ubsan.c b/arch/x86/kernel/ubsan.c
> > new file mode 100644
> > index 000000000000..6cae11f4fe23
> > --- /dev/null
> > +++ b/arch/x86/kernel/ubsan.c
> > @@ -0,0 +1,32 @@
> > +// SPDX-License-Identifier: GPL-2.0
> > +/*
> > + * Clang Undefined Behavior Sanitizer trap mode support.
> > + */
> > +#include <linux/bug.h>
> > +#include <linux/string.h>
> > +#include <linux/printk.h>
> > +#include <linux/ubsan.h>
> > +#include <asm/ptrace.h>
> > +#include <asm/ubsan.h>
> > +
> > +/*
> > + * Checks for the information embedded in the UD1 trap instruction
> > + * for the UB Sanitizer in order to pass along debugging output.
> > + */
> > +enum bug_trap_type handle_ubsan_failure(struct pt_regs *regs, int insn)
> > +{
> > +       u32 type = 0;
> > +
> > +       if (insn == INSN_REX) {
> > +               type = (*(u16 *)(regs->ip + LEN_REX + LEN_UD1));
> > +               if ((type & 0xFF) == 0x40)
> > +                       type = (type >> 8) & 0xFF;
> > +       } else {
> > +               type = (*(u16 *)(regs->ip + LEN_UD1));
> > +               if ((type & 0xFF) == 0x40)
> > +                       type = (type >> 8) & 0xFF;
> > +       }
> > +       pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
> > +
> > +       return BUG_TRAP_TYPE_NONE;
> > +}
> 
> Shouldn't this return BUG_TRAP_TYPE_WARN?

So as far as I understand, UBSAN trap mode never warns. Perhaps it does on
arm64, although it calls die() so I am unsure. Maybe the condition in
handle_bug() should be rewritten in the case of UBSAN ud1s? Do you have any
suggestions?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2j6nkzn2tfdwdqhoal5o56ds2hqg2sqk5diolv23l5nzteypzh%40fi53ovwjjl3w.
