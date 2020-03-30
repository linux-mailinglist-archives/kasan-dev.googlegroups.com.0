Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBVPBQ32AKGQEKMTIP4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A2F01976CC
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Mar 2020 10:41:58 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id f19sf15277256edt.5
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Mar 2020 01:41:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585557718; cv=pass;
        d=google.com; s=arc-20160816;
        b=EUSm3qZ0LsDwspt9KJ0i+x7lTLhJ0kGOGLwD7rbOxTgrQPRPURLp0mgBDID1LdNbu2
         uZKr/62q0GPeo2tryRNCGvLQ644kFIawFsNVoClkme57MXCYuMymwGkit3+jLEqik7id
         09KUvQuZVkIjzo7wO+25zXHpyFp8EgTWKEfSIFyRIZc4kK64eEewNS5rhZWiCNvAKWYU
         KvqtclWYKNgEGMiMrnQl7PgkhfiKlOFqNBpEB8K9Zx7vrEY7RLB7OgROHVQskHNm5giK
         v0reZVbnKsnTWIghJFZG/fGEBs6r6FG+3VIgYiLGeO/ZV1yqgJ1o5lbn5gXyAJyOGO0i
         FWTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=4oZc0w4C0oMjsuiphIyPyuTThVuJXuyPvUUaQWRH7kE=;
        b=pw41/PkbqaToqeveSsW/u5ShtVB/n+69edR6m6UPmtCzA1/UkX0N/F07AkS1QnDkdq
         qZmNiW9NALNAVUURM13kTdmueZTk7Tfwht43MgunNBmPNrLbjjpbJ5+5ZL5fcU5BGEsE
         pGPVqS6IDfa2PSXTXLEjjqyrgbJdIVbqLe3Mk5Ln5liynXTFnYU/PR3l0siEQ2CB7Sl1
         DfJt33W+3Cndi4OFdQd+ug92ywuHEv3NXg/LzlNZtzIlydY6UwiixQX3htY3FwDj0tc3
         1kAl9JbJ8BQZAwqeVRnU3/sdlqv62JbKQUsH06efS6AVPYYMh7lReCS/PhreopDZmuqG
         RKbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4oZc0w4C0oMjsuiphIyPyuTThVuJXuyPvUUaQWRH7kE=;
        b=h7soJjymOLrpQ4I8EX4lkKHBg0uHWZnFuMLTy8/9l0bIeIhG0ZpZnelPbOEIK6Jy+G
         bXmdYA6UaJJlhJY/ntUJ8/414lmfznT8PmrpvXiPYUzrEMyWNx4ZdVUy9J7x2U3+5mbW
         0PYT+yQ5eVPzyOSx3RHQ6ABthAp+7J1HEwBE7v4OND0s5CZSUl037eVq1zhTlbtv5g8z
         fAladD/ggFRjbRAFlaRv2WtkeQ9CC7FrPw5+ONK34DfqxA6U0Bb5Gj//WjwVI26ii+SQ
         rAjcpvOY4t+oDGfGMppc7jZfF9IHewPJ0p6s0LBr3+6bYAZCKyTf7dPfwA4MaIT3VJno
         ZDvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4oZc0w4C0oMjsuiphIyPyuTThVuJXuyPvUUaQWRH7kE=;
        b=d2oZ0VNEm4msDBCQTDGagHGIRaPN70iMwY2/RpmPHnSkzOrheq1D+2W+S22T1Bz42e
         XTNyeMe1ZZdA/BD+nwfgVMcBxGIcSsa1+q2xJ/BHhlqgS6G8Zxa/i5JO6w9pF9rrRtnC
         uIIn6OLjhgU3m3NbAYGuOHKG+xJRE+Bynakxvxkmi06hfKcbv89ODxeAkbqTt+M0Hp8n
         hjEcQVm21jcjqPfObOL5cu17PGF5BRZnIO1nlbjb+iM7Alk9V9ZfDsoGuliXj3WSO5MD
         kX6oFKhCkSEnd6Rc3yp7zOrXYhcy9GAiXEms/uZWRKZ0JYIgXRS67zaR/A0vErC9souF
         8Jtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3C6FxvUuc3t+1MJAQoJz/5DIflXlezS7ucip3h8qpjB4RCsQpL
	KVobogOQAh5IS5zqladYeeA=
X-Google-Smtp-Source: ADFU+vu9211T7n9wpYBcbzyVWn8JLzaRTvmlpxOXFgr1jaa1KXy4nhju0lKCsDylnlE3QuFvoCZ9yg==
X-Received: by 2002:a17:906:a2c6:: with SMTP id by6mr10064661ejb.350.1585557717671;
        Mon, 30 Mar 2020 01:41:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:a40f:: with SMTP id u15ls13009239edb.5.gmail; Mon, 30
 Mar 2020 01:41:57 -0700 (PDT)
X-Received: by 2002:aa7:d614:: with SMTP id c20mr10768545edr.232.1585557717057;
        Mon, 30 Mar 2020 01:41:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585557717; cv=none;
        d=google.com; s=arc-20160816;
        b=oYlcDDSYxKUL8UoBcQS29OQyNUNWCdI7ZCG5JNB9YL2tAjkDA6OW1qeMI+LiWRqoZS
         qgQrMDCPq3DczJcAfUwbiW4hTblA8+COR7JIaliskJB6WZeQkoj5gX10Acxs/7S+3KaX
         2Rs3g4SQhM0TWYyxiYOY5Bj0SXCbFtIHVwdJQCjvv/KytjTmksI25+GNTs8NzGB7p64a
         TQOZo3lP8AuXlA35OoGeifNMZ29PYgKNDvhPW/INFq5VsvCT/hWHkaVF+n1nL8zrlUCP
         W08XikszpesehtPd+cFRJ/c5lx9F/01pJFcmGvAlcjy2ozGsZi1S0CaxQhFnbKcXZmKx
         XFlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=t1AP1Z+DLp+G+REyxDxIG8hH7ooygsBWX8eGtMxKgIE=;
        b=aBU147E+ZIAC3mOZU7kslk6juvK3wxNSdI025d8fkZu2Qg9/96+QPXC0qGowZMsig5
         a9mI+qlw2hZnYw2luP4D7ziWr7GjuxdVbcb/rZbpCsSvOtNW2jeoq4NJEU2cEwIgn2+2
         96C0MZEZUlfjA7uryCtGWZLfbPBHvBKtUIP4UQGF0xf1rnCy1Slni1b2ljWpAHih+xsG
         84aIL0oIqXefqAVXoM8/b3Fg+xCyYmkqSAcJMQC83FLeOvpgSnLVN3hANM5K/MrqMTXs
         f09wEe7EKERXdwj6OzxQ/xhMo0ef+AkDv0BspGKDUaz2S1frYbQjw4nw7GgHnPBqaFia
         RCHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id v14si695616edr.4.2020.03.30.01.41.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Mar 2020 01:41:57 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1jIpzM-005Qx3-IU; Mon, 30 Mar 2020 10:41:44 +0200
Message-ID: <a51643dbff58e16cc91f33273dbc95dded57d3e6.camel@sipsolutions.net>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike
 <jdike@addtoit.com>,  Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Brendan Higgins <brendanhiggins@google.com>,  David Gow
 <davidgow@google.com>, linux-um@lists.infradead.org, LKML
 <linux-kernel@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
Date: Mon, 30 Mar 2020 10:41:43 +0200
In-Reply-To: <CACT4Y+YhwJK+F7Y7NaNpAwwWR-yZMfNevNp_gcBoZ+uMJRgsSA@mail.gmail.com> (sfid-20200330_103904_296794_2F7C15A1)
References: <20200226004608.8128-1-trishalfonso@google.com>
	 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
	 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
	 <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
	 <CACT4Y+bdxmRmr57JO_k0whhnT2BqcSA=Jwa5M6=9wdyOryv6Ug@mail.gmail.com>
	 <ded22d68e623d2663c96a0e1c81d660b9da747bc.camel@sipsolutions.net>
	 <CACT4Y+YzM5bwvJ=yryrz1_y=uh=NX+2PNu4pLFaqQ2BMS39Fdg@mail.gmail.com>
	 <2cee72779294550a3ad143146283745b5cccb5fc.camel@sipsolutions.net>
	 <CACT4Y+YhwJK+F7Y7NaNpAwwWR-yZMfNevNp_gcBoZ+uMJRgsSA@mail.gmail.com>
	 (sfid-20200330_103904_296794_2F7C15A1)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.4 (3.34.4-1.fc31)
MIME-Version: 1.0
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

On Mon, 2020-03-30 at 10:38 +0200, Dmitry Vyukov wrote:
> On Mon, Mar 30, 2020 at 9:44 AM Johannes Berg <johannes@sipsolutions.net> wrote:
> > On Fri, 2020-03-20 at 16:18 +0100, Dmitry Vyukov wrote:
> > > > Wait ... Now you say 0x7fbfffc000, but that is almost fine? I think you
> > > > confused the values - because I see, on userspace, the following:
> > > 
> > > Oh, sorry, I copy-pasted wrong number. I meant 0x7fff8000.
> > 
> > Right, ok.
> > 
> > > Then I would expect 0x1000 0000 0000 to work, but you say it doesn't...
> > 
> > So it just occurred to me - as I was mentioning this whole thing to
> > Richard - that there's probably somewhere some check about whether some
> > space is userspace or not.
> > 
> > I'm beginning to think that we shouldn't just map this outside of the
> > kernel memory system, but properly treat it as part of the memory that's
> > inside. And also use KASAN_VMALLOC.
> > 
> > We can probably still have it at 0x7fff8000, just need to make sure we
> > actually map it? I tried with vm_area_add_early() but it didn't really
> > work once you have vmalloc() stuff...
> 
> But we do mmap it, no? See kasan_init() -> kasan_map_memory() -> mmap.

Of course. But I meant inside the UML PTE system. We end up *unmapping*
it when loading modules, because it overlaps vmalloc space, and then we
vfree() something again, and unmap it ... because of the overlap.

And if it's *not* in the vmalloc area, then the kernel doesn't consider
it valid, and we seem to often just fault when trying to determine
whether it's valid kernel memory or not ... Though I'm not really sure I
understand the failure part of this case well yet.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a51643dbff58e16cc91f33273dbc95dded57d3e6.camel%40sipsolutions.net.
