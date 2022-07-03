Return-Path: <kasan-dev+bncBC42V7FQ3YARB5FIQSLAMGQELSMWDHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-f62.google.com (mail-wm1-f62.google.com [209.85.128.62])
	by mail.lfdr.de (Postfix) with ESMTPS id 171A25643EF
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Jul 2022 06:00:53 +0200 (CEST)
Received: by mail-wm1-f62.google.com with SMTP id n18-20020a05600c501200b003a050cc39a0sf2743043wmr.7
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Jul 2022 21:00:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656820852; cv=pass;
        d=google.com; s=arc-20160816;
        b=OuW64t7VzAfIT9SbbPLVnGuw3wZxUHZSLs4OpcNCYPd9rD8Ud8skGn1hcpmzmnsBDJ
         aY/F+V5oV6K9DBKvaCZo4y1h56LTtagmexeGcGaa2AYATws/zVmOVbEO/scsGqsz1EEi
         Wk9vQzWy/0UViyjxokz0rHyEP8LKWwhrHDlsEfazgo8krACaYIAfhkVRK7ANltf6mZu5
         wqqsaBl0KFB83BC+Zj8B31znSQDN3a7KOgJ/WwKWj3oWCXD48Mm8DUmTFEYbdg63VgcL
         qtxcuQOnEu94F6cWgQkbAUtKK5gXuSGKCLNaMqA/k3iKSLlxoUZ63Kce/wVnr9RtSKUJ
         gZ3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=C0+nU90oaNY+lIuRQUSSaowlj9IH3Y8WlvzAyjVmwu4=;
        b=hQwJGcgfdAQ10L3KnGbKs3chy7ej6a4QztPIbu8K8Lk5vDaNH3q3fp/AzY5A/VAeRO
         mKHH13dqF2Byo/WrkgIjdxCoqEfa6XObsMlntwdYhGLhUEGIYFDTgxz1yCjqkEMWl045
         PJZQ1YfQxJ1l7/hW+/FDbkcsqYe4LE2E7DKNB4Li6zpqoNG8kEeBJTNg+zd96q2nCTwg
         tQ45WDGDw7AU3OSYwXgzpn+OkDepBfKkzEz8y9glvEXG52t8NWiweaHrPZljvjbiCTSD
         rd734NIDFKDlsLnIUBKscNFrfcEXxv08+PudM061zUdV9pSGTH9cOSFjS1tEAJ8rL3hK
         F3tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=SlO+fKNy;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C0+nU90oaNY+lIuRQUSSaowlj9IH3Y8WlvzAyjVmwu4=;
        b=sJassC6w6Tv97UWE4nuiGO6zn2WdCnaX+2RolSil4LNoy8yw/lATrFZLsBWcGNONgL
         85KX53j8GYBco9qlC1TBuICOcS5KSwN0cGv4DDqNMTMSjFZvP4evFVJfRy8mOFskrZWF
         PYXv4R4nFQeMf9Bgn07XzepatOxzX5fmgnel+pMmFnbsMHTpRrej6MBI6GridrDiq2/c
         b4a9OB1jNJIY6LzzMUOiPqHKLe8TrnV/0XuOfBapYNwEG6J/8KJZYavfB7ZqsJXRNIMV
         Sdtx3kqMt2F4LQnroYm42iVPSZ8BU3yst19XX1VE0ZDtS2m4CAIhCrYVnc1YeuqW9bj2
         7BIA==
X-Gm-Message-State: AJIora8pek4AjkFkHWX8yB8lBMpnXKk66RlCq+SY/idMaHIfmAV39+N4
	g593XGLZvopNlXvfgeb2eiQ=
X-Google-Smtp-Source: AGRyM1sDMD5YLb+7DFf7dQjfyPcY7X6sda7FHT1hjDaHau0cOEHxDbVWNuswERMBTb9QCEqq0yAs0Q==
X-Received: by 2002:a5d:6752:0:b0:21d:6400:6b4b with SMTP id l18-20020a5d6752000000b0021d64006b4bmr3318851wrw.396.1656820852525;
        Sat, 02 Jul 2022 21:00:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:47ce:0:b0:21d:339f:dc1 with SMTP id o14-20020a5d47ce000000b0021d339f0dc1ls15255505wrc.0.gmail;
 Sat, 02 Jul 2022 21:00:51 -0700 (PDT)
X-Received: by 2002:adf:f503:0:b0:21a:3d9c:b355 with SMTP id q3-20020adff503000000b0021a3d9cb355mr19893226wro.623.1656820851351;
        Sat, 02 Jul 2022 21:00:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656820851; cv=none;
        d=google.com; s=arc-20160816;
        b=Q/pIwf1nmhADmBAT16ciKApjhE8iiWVbaGMxf+6g6w1fJUjSYPSMIcDMioNdDJBD0s
         2jU6Oaeb6JZeOGbxsPjUiE5QYM1CY4cdoesMFapz6+TYQ+MCN4P4Apy+rFu6pErp0Kn7
         qsiwwpY5IMFTZNsexfoTgHl0msZ6GfM/c2lkSTBvCiTsQZXLoMp05MsjcGFVmPJca/bh
         xY8r36k2A6zY9trdAALyrUSqQBT8vVvUOAZiGMzVeesP5WKvDWfBiDfA4xjCedaxwtdS
         iKmNoFP7ysjsuN942UdMUKjOJsB6o0/4KIVS77VEj4F0SojsGJO6m9QVI3XmeMM/lpg6
         Qq8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LQzNJSrqoKMb8FMCvc/7lp2Km4cof1d6Hftc45fNj1g=;
        b=0sQ1f3wrOB7GUZeLR/uThhBePxC8iwaE+wnALPu2lU8w6+lLRhjD7Wm8pQMk5R/w9c
         9UzEKExlbw7rgKvGL8CvniGhdf66BaOVffv4v+E94iB0Y/k3GAm0mqeArdQY1vwwN+NE
         p65/8fdPmjzNozGABrPXy6wCEJqNT90InmWujY65g6uA0+q96go0MHFvkkhGQskei2je
         50rzHg+oei29HkiFzYvikvLHKiifoJtYMx3YWCwMMSjNNgdAPAVVOU7D4DIdOko+v4BK
         Hnnz0fCyLHAj+NN6tUTIyRPX1Z0E/kXPM7V+XQufVGpeVDLrS1YsSsk7srEsj/m0BmMU
         klpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=SlO+fKNy;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id az26-20020a05600c601a00b003a033946319si477081wmb.0.2022.07.02.21.00.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 02 Jul 2022 21:00:51 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o7qlz-007YYP-Mg;
	Sun, 03 Jul 2022 03:59:51 +0000
Date: Sun, 3 Jul 2022 04:59:51 +0100
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
Subject: Re: [PATCH v4 43/45] namei: initialize parameters passed to
 step_into()
Message-ID: <YsEUNyKcIiSowfIR@ZenIV>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=SlO+fKNy;
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

On Sat, Jul 02, 2022 at 10:23:16AM -0700, Linus Torvalds wrote:
> On Fri, Jul 1, 2022 at 7:25 AM Alexander Potapenko <glider@google.com> wrote:
> >
> > Under certain circumstances initialization of `unsigned seq` and
> > `struct inode *inode` passed into step_into() may be skipped.
> > In particular, if the call to lookup_fast() in walk_component()
> > returns NULL, and lookup_slow() returns a valid dentry, then the
> > `seq` and `inode` will remain uninitialized until the call to
> > step_into() (see [1] for more info).

> So while I think this needs to be fixed, I think I'd really prefer to
> make the initialization and/or usage rules stricter or at least
> clearer.

Disclaimer: the bits below are nowhere near what I consider a decent
explanation; this might serve as the first approximation, but I really
need to get some sleep before I get it into coherent shape.  4 hours
of sleep today...

The rules are
	* no pathname resolution without successful path_init().
IOW, path_init() failure is an instant fuck off.
	* path_init() success sets nd->inode.  In all cases.
	* nd->inode must be set - LOOKUP_RCU or not, we simply cannot
proceed without it.

	* in non-RCU mode nd->inode must be equal to nd->path.dentry->d_inode.
	* in RCU mode nd->inode must be equal to a value observed in
nd->path.dentry->d_inode while nd->path.dentry->d_seq had been equal to
nd->seq.

	* step_into() gets a dentry/inode/seq triple.  In non-RCU
mode inode and seq are ignored; in RCU mode they must satisfy the
same relationship we have for nd->path.dentry/nd->inode/nd->seq.

> Of course, sometimes the "only get used for LOOKUP_RCU" is very very
> unclear, because even without being an RCU lookup, step_into() will
> save it into nd->inode/seq. So the values were "used", and
> initializing them makes them valid, but then *that* copy must not then
> be used unless RCU was set.

You are misreading that (and I admit that it badly needs documentation).
The whole point of step_into() is to move over to new place.  nd->inode
*MUST* be set on success, no matter what.

>  - I look at that follow_dotdot*() caller case, and think "that looks
> very similar to the lookup_fast() case, but then we have *very*
> different initialization rules".

follow_dotdot() might as well lose inodep and seqp arguments - everything
would've worked just as well without those.  We would've gotten the same
complaints about uninitialized values passed to step_into(), though.

This
                if (unlikely(!parent))
                        error = step_into(nd, WALK_NOFOLLOW,
                                         nd->path.dentry, nd->inode, nd->seq);
in handle_dots() probably contributes to confusion - it's the "we
have stepped on .. in the root, just jump into whatever's mounted on
it" case.  In non-RCU case it looks like a use of nd->seq in non-RCU
mode; however, in that case step_into() will end up ignoring the
last two arguments.

I'll post something more coherent after I get some sleep.  Sorry... ;-/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsEUNyKcIiSowfIR%40ZenIV.
