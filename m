Return-Path: <kasan-dev+bncBC42V7FQ3YARBX7JR2LAMGQEY3YUB4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-f62.google.com (mail-wm1-f62.google.com [209.85.128.62])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FB2C5661FC
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 05:49:52 +0200 (CEST)
Received: by mail-wm1-f62.google.com with SMTP id az40-20020a05600c602800b003a048edf007sf4731104wmb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 20:49:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656992992; cv=pass;
        d=google.com; s=arc-20160816;
        b=0SAXYyx+/qdUc9VXOOsbgZ0qTc2zSQjdc0KXutqsp4Cj4oC6XQzXQF8Bb9pybVJJG4
         UdSDHZL4I81lE46BZilM9ymawsKHPa6aW7I2PRRR9GuAkbBMDfVRkMLETKrjD1nzDtU5
         vKa4X8i4mehE8SOPK605nA1YUp4R5n3N7p6unWRc6DivSnTaLoYynRWPH2T6W7Bmg0zl
         yCCGfpmiSYgGmerNzR9tSVDy82PQ9owPiRSfTN3fg97EK9u45vDPkoyMoki1P02WLQfC
         Qybfv/77jI2iOZfffdnjl7TldNYYE7K53qe5Q+fyIMC5tGTlJXNHxUfvNQKrNXxdqS6+
         xuNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=wQ0R5yEA8eO0KpvrOPAUGa0iMKa8ZtnK4yq965Y5P2Q=;
        b=KAFAzrfPLQc3lrVugAwiEOsSSd8/04xTDjWfKcCG4UG53exkiDDKLwf0FDjXU5znj8
         ZcnohGqcS9D1X/nvr0rLy0WsrxfCWcJakt233fMhSQcadokKECDgjC1fysc2FvUco53j
         VYuoQAqtpx4VxldeCFCZaJU+zMfhsjMRh8YGArW5kJu14pDakUvLbH0SskILVJqVuVw9
         ovERQ3r5F+yhCgSBZxFMWKkB3wipyvHNuD7AmuoM1ShN043vLbh9oFOdqSyQdI8mXFdm
         1/ZrYl5EVIxcQB2CRlJfQ9z6s1R8TAnz7c9S6xDRihtNE+Jl3RAz6WMME5VLjYnCFdX4
         2BMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b="A6t/lG34";
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wQ0R5yEA8eO0KpvrOPAUGa0iMKa8ZtnK4yq965Y5P2Q=;
        b=N/FMcKoRQCndVTPKM2HBKOKD5TA8j2knP/0OPDyN7TQtOZa/E7j5ipQtYYu6XgfzJC
         K9PFEAMFVr3UTRmHwSF3h8h3IDfedJtH6cvCSU5DoR1F916z00GU8+ZRon1TDtba4Q16
         LNkNVqQ4EmuZe+ziP/Xa7lQrIpJ2MAdOLnUWEBkQXJ8d1IkqD53y43S1XRxGcKsUhRhQ
         5+CPwHdxxTEzdtqJisW0Kip+x3qSR9sqR9RqUI+OYc0zYRxcyd+xuRQhEr2AzmX+mvF1
         MVg3ituI41aZXx6p427CtqBlBfJQFb40B2B4SDh9MpmRp8aty+VHFrvqAufwVQKdl3st
         vtoQ==
X-Gm-Message-State: AJIora9wklmukEDVtD6ayx66llszAWrUv9sK9Vhl1GYRAPAVotijN6lt
	hWU1BxHFpB/F6n7iDOhGyc8=
X-Google-Smtp-Source: AGRyM1th1+urkXmp1YBUe/67iChD4JXba2ayhVoEflnYMf+wE6J0t6DXQ5lkXu5saldfAm7IHJqO8w==
X-Received: by 2002:adf:dc0d:0:b0:21d:ea5:710f with SMTP id t13-20020adfdc0d000000b0021d0ea5710fmr29881919wri.48.1656992992160;
        Mon, 04 Jul 2022 20:49:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:156e:b0:21d:2eb7:c707 with SMTP id
 14-20020a056000156e00b0021d2eb7c707ls24994889wrz.3.gmail; Mon, 04 Jul 2022
 20:49:50 -0700 (PDT)
X-Received: by 2002:adf:e112:0:b0:21d:7195:3a8d with SMTP id t18-20020adfe112000000b0021d71953a8dmr1407787wrz.371.1656992990841;
        Mon, 04 Jul 2022 20:49:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656992990; cv=none;
        d=google.com; s=arc-20160816;
        b=ovhFF6QevQoE5Ql8a39OhXOEebIIXIgdOf6cBFtIFrw8QN8S9/YfZiU5diRERePdSp
         xvoAW3F0Of6/HvmyHrwvNJTirrI+Xaj6kh4tqgxOCxA71U73gLZPARfQNWH7apKoevB6
         gj1cL7Pnz/k16U3M8y4L/vLAupLXFlzFvRqicIQBRbCpnj7JRYgri/udE/mTd0mCNq+0
         jVZo6lpGr47sWOGdpqy6xMYOPpkPglXrbDeg/UlFEYSNLchts1ZuXEQogRYmMPJJ8lhG
         nyTU/gTUIgt3lk+GeTZhCCK0GOLAAP8qIVmdJ806aurZwis1xSWd4u1K3WL6cju4Gfy8
         78+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=WiklvS9k0el8XhEQTp2AsFsJfZTmp2j5g87JdjG5LuY=;
        b=gGloQG8KpBFPSlVxg3mrtQUqjLlIQoEsSkpzbRMZaA0MpDPWvl+LwTroc02kCYrQCr
         tS8THOXWxwItPOVRpWRzIfp5p7m7eLYvBjUju2RTzpDJxvBfXF+5cuJL0bLaZUdFw8RS
         zJqNFq/tzKcvEzVX/1FUKcDnPGaeMvgl77HxZNhdxAt7dydEkJTBrgZjyIJm+Ss4wftI
         87hFRepF5EVgjUA/uUQuXg/5pP1s45DA5g1pasyJkE656ChTtIin/2JglTXCWsDmeBp5
         deS2JfqwY/H8TGVNazmcHhxtlSgL8BRyE1Qz/ckfDELYj1QNAfdU3LmNFKZ1G9dd28+W
         RkAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b="A6t/lG34";
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id bn26-20020a056000061a00b0021d6e648fd1si102265wrb.1.2022.07.04.20.49.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 20:49:50 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8ZYY-008EUH-Gz;
	Tue, 05 Jul 2022 03:48:58 +0000
Date: Tue, 5 Jul 2022 04:48:58 +0100
From: Al Viro <viro@zeniv.linux.org.uk>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthew Wilcox <willy@infradead.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Segher Boessenkool <segher@kernel.crashing.org>,
	Vitaly Buka <vitalybuka@google.com>,
	linux-toolchains <linux-toolchains@vger.kernel.org>
Subject: Re: [PATCH 1/7] __follow_mount_rcu(): verify that mount_lock remains
 unchanged
Message-ID: <YsO0qu97PYZos2G1@ZenIV>
References: <YsM5XHy4RZUDF8cR@ZenIV>
 <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
 <YsNFoH0+N+KCt5kg@ZenIV>
 <CAHk-=whp8Npc+vMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA@mail.gmail.com>
 <YsNRsgOl04r/RCNe@ZenIV>
 <CAHk-=wih_JHVPvp1qyW4KNK0ctTc6e+bDj4wdTgNkyND6tuFoQ@mail.gmail.com>
 <YsNVyLxrNRFpufn8@ZenIV>
 <YsN0GURKuaAqXB/e@ZenIV>
 <YsN1kfBsfMdH+eiU@ZenIV>
 <CAHk-=wjmD7BgykuZYDOH-fmvfE3VMXm3qSoRjGShjKKdiiPDtA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wjmD7BgykuZYDOH-fmvfE3VMXm3qSoRjGShjKKdiiPDtA@mail.gmail.com>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b="A6t/lG34";
       spf=pass (google.com: best guess record for domain of
 viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted
 sender) smtp.mailfrom=viro@ftp.linux.org.uk;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=zeniv.linux.org.uk
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

On Mon, Jul 04, 2022 at 05:06:17PM -0700, Linus Torvalds wrote:

> I wonder if the solution might not be to create a new structure like
> 
>         struct rcu_dentry {
>                 struct dentry *dentry;
>                 unsigned seq;
>         };
> 
> and in fact then we could make __d_lookup_rcu() return one of these
> things (we already rely on that "returning a two-word structure is
> efficient" elsewhere).
>
> That would then make that "this dentry goes with this sequence number"
> be a very clear thing, and I actually thjink that it would make
> __d_lookup_rcu() have a cleaner calling convention too, ie we'd go
> from
> 
>         dentry = __d_lookup_rcu(parent, &nd->last, &nd->next_seq);
> 
> rto
> 
>        dseq = __d_lookup_rcu(parent, &nd->last);
> 
> and it would even improve code generation because it now returns the
> dentry and the sequence number in registers, instead of returning one
> in a register and one in memory.
> 
> I did *not* look at how it would change some of the other places, but
> I do like the notion of "keep the dentry and the sequence number that
> goes with it together".
> 
> That "keep dentry as a local, keep the sequence number that goes with
> it as a field in the 'nd'" really does seem an odd thing. So I'm
> throwing the above out as a "maybe we could do this instead..".

I looked into that; turns out to be quite messy, unfortunately.  For one
thing, the distance between the places where we get the seq count and
the place where we consume it is large; worse, there's a bunch of paths
where we are in non-RCU mode converging to the same consumer and those
need a 0/1/-1/whatever paired with dentry.  Gets very clumsy...

There might be a clever way to deal with pairs cleanly, but I don't see it
at the moment.  I'll look into that some more, but...

BTW, how good gcc and clang are at figuring out that e.g.

static int foo(int n)
{
	if (likely(n >= 0))
		return 0;
	....
}

....
	if (foo(n))
		whatever();

should be treated as
	if (unlikely(foo(n)))
		whatever();

They certainly do it just fine if the damn thing is inlined (e.g.
all those unlikely(read_seqcount_retry(....)) can and should lose
unlikely), but do they manage that for non-inlined functions in
the same compilation unit?  Relatively recent gcc seems to...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsO0qu97PYZos2G1%40ZenIV.
