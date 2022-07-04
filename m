Return-Path: <kasan-dev+bncBC42V7FQ3YARBWFDRWLAMGQE25JZXBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-f184.google.com (mail-lj1-f184.google.com [209.85.208.184])
	by mail.lfdr.de (Postfix) with ESMTPS id 99C49565E9F
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 22:47:21 +0200 (CEST)
Received: by mail-lj1-f184.google.com with SMTP id m8-20020a2eb6c8000000b0025aa0530107sf2953405ljo.6
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 13:47:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656967641; cv=pass;
        d=google.com; s=arc-20160816;
        b=m/dZAuiKJp9ZoKzo262exnPDo2C7zcDnz/GyClKiF+MfkNgALzR4IxsJ6w+RLQi7u/
         +kEp0M4D5g0I3V3/H240qmWsc1Rg5GgXFBO1i4Z7rJnmJmjt14CXdOKUOGY7pSI6oHpx
         u7CHl5tSKjbMoh5ykPETEyHsvhyl+3mPHW3r27ZSffm4Dc4jGIaIhJheJqxWWO1tQ1xg
         eO7nmwf9owDQyaAarBX0sOjD2Zjt6bDkp4PCeIb71EDTJMSCwb0wBBSHLAYrLWCDBGco
         z56Qvs44HbdVyrVl1fUW/HpIheee6SaHvQfLiDgx+s3OPzjhyue1pMMhLhkipkyT7NQw
         klSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=9lB1xC3RAZZ3u4QRVj0heqflkCYpL+v6QNPWE91DZE8=;
        b=aGrgLYN4ZwyHVZKokhy5UxhzTiDrJ6ONTViqclIPcAJ7Td9OqrtBQVJatTwt6zwsCU
         xxGUazehJ1IhzabIy5u6eyXzWpOtmPPxoaxdPPrqlEbRZy01bAyLuDSj6kHjljz+wmF1
         +Tt77N74le4E2AVJY+EmRskEI6qO+zxxVD5aTjB412BjIhBn+EBBGlDmciZ6GQeU14IZ
         7DF+Z96WjTWDqsQD6fb42o/JtqlWQBCmfAf3ZBVyDOKdBk8RbA1riBZtcnU/hrQsw5fx
         V2div7jRZ2FIrVgnr2tR+j/JGMOX/Gbe26MxdMD/gFkvYcsfEAaqnhrdWEFFGiScl1sZ
         MYZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=JqCpfM5+;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9lB1xC3RAZZ3u4QRVj0heqflkCYpL+v6QNPWE91DZE8=;
        b=fNSX1+sAN6QjZ7OfSypNUJsCY1k9AyLqcSwFdRiNNyqgS7aRtuzKsJpSVu3/g/cyoL
         CjCjJEQdR8wQuk6OcUZrqs9Cwzl/TtYrLbXxzhMDz1LAHYDBxXlhtraXSI1vnjg7s3wU
         zQ0uXtFe+wFbKeUbZnTV6/2E8pGduIc+kcq5ifMzlXPUz4ftlJo+a+EoSubf1GHGN/fI
         b/SChOOpc7gSQddSBeuuC1Sxvd9mP2Jh7jP1uDase+pM7mW/CrKRg+gfaounJtxVLvY6
         C8txGM5myRHqtmBbNFLDZmP+ORJkIxxpWPWedGf4bmEyueOXsXlC86B3CFF4lbP3byVs
         rAww==
X-Gm-Message-State: AJIora9AfAiBE29AGkM3w8xq0wwVKEjUYtXLwgY7HI93ai/ifR++rvws
	84srBu2ieImffHCozaNXOZI=
X-Google-Smtp-Source: AGRyM1t6SKBUT0jqUydUe9I2gLXUeDRtpkSkwXAIyp6lfw1GLU+JCBC7vM5qcye2Ier+EoNdExYf4g==
X-Received: by 2002:a2e:91c4:0:b0:25a:7256:a7aa with SMTP id u4-20020a2e91c4000000b0025a7256a7aamr17139815ljg.344.1656967641176;
        Mon, 04 Jul 2022 13:47:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls67627lfv.3.gmail; Mon, 04 Jul 2022
 13:47:19 -0700 (PDT)
X-Received: by 2002:a05:6512:1506:b0:47f:79c6:eb36 with SMTP id bq6-20020a056512150600b0047f79c6eb36mr21484501lfb.168.1656967639385;
        Mon, 04 Jul 2022 13:47:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656967639; cv=none;
        d=google.com; s=arc-20160816;
        b=XNFHYsrPK8fzYSuoydTMp2tH/B11cqVE/agTPk3Q6CIjXVfdtGbzCkEJfP/m9zzokb
         LzKr4JSLxUqkywWsEoLKBIaJRGxdgA2w7oxeWjK65uuTx2wlQKooHDY5JT3F1vtyMiw4
         v+5cPbB4h0wGgESbKXB1SN6pbF3t1HxWyePTdrk7FdTo1W6RTb0Xq5spvXtI8J9oKykG
         i33t3eBNbe2wAbFBSYNpfw/EmcZliWXsut1Ju6A2FArXmKRUh/drOO1yOmFuW/FjUG1D
         9Df9w1dlmZHlgfvoEN00QsONaQbjzQS5ylEQ5eJf7fBuXI9+ekB1YCDxNWLMS6FFKaUz
         ry+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Q731IdPTtbWT2I3vbiClRvKMIPfhcPeg7PDkz8ljupo=;
        b=ymhznQNTs/h2w4Eg/pkOx37s5ofQZQxWSJaHnKSE/B9oaKGuAWA8xKJ9DVH9eX1ZQ3
         r+Q27SX3DXkt69EarJFfelkj5AhX/I4wA+9St4E0AbF5cTSSJa7t48bdYk35wnrChIC3
         sFaxkowRxQO2rvvnkdAd3HHaLIRZhEXyu1NCqpAyUY8IQVH+l2WZ1manUep2KNJHIUG5
         pIcSbg2p5zpYeYobdyNafEeWDuzHT/U5iwe+KHZXMKA3qOKMCfdKFpo7f2H3x47KwhW2
         yMfUdyAA5TAEEF+qCbY17SrkmUlNUC0G6//s8dDrIMj0Gbt1r/9Muaz7oWPRyZ7UWneQ
         CEXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=JqCpfM5+;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id t28-20020a05651c205c00b00258ed232ee9si1136038ljo.8.2022.07.04.13.47.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 13:47:18 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8Sxv-0088VZ-0F;
	Mon, 04 Jul 2022 20:46:43 +0000
Date: Mon, 4 Jul 2022 21:46:42 +0100
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
Message-ID: <YsNRsgOl04r/RCNe@ZenIV>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV>
 <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
 <YsM5XHy4RZUDF8cR@ZenIV>
 <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
 <YsNFoH0+N+KCt5kg@ZenIV>
 <CAHk-=whp8Npc+vMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=whp8Npc+vMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA@mail.gmail.com>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=JqCpfM5+;
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

On Mon, Jul 04, 2022 at 01:24:48PM -0700, Linus Torvalds wrote:
> On Mon, Jul 4, 2022 at 12:55 PM Al Viro <viro@zeniv.linux.org.uk> wrote:
> >
> > You are checking the wrong thing here.  It's really about mount_lock -
> > ->d_seq is *not* bumped when we or attach in some namespace.
> 
> I think we're talking past each other.

We might be.
 
> Yes, we need to check the mount sequence lock too, because we're doing
> that mount traversal.
> 
> But I think we *also* need to check the dentry sequence count, because
> the dentry itself could have been moved to another parent.

Why is that a problem?  It could have been moved to another parent,
but so it could after we'd crossed to the mounted and we wouldn't have
noticed (or cared).

What the chain of seqcount checks gives us is that with some timings
it would be possible to traverse that path, not that it had remained
valid through the entire pathwalk.

What I'm suggesting is to treat transition from mountpoint to mount
as happening instantly, with transition from mount to root sealed by
mount_lock check.

If that succeeds, there had been possible history in which refwalk
would have passed through the same dentry/mount/dentry and arrived
to the root dentry when it had the sampled ->d_seq value.

Sure, mountpoint might be moved since we'd reached it.  And the mount
would move with it, so we can pretend that we'd won the race and got
into the mount before it had the mountpoint had been moved.

Am I missing something fundamental about the things the sequence of
sampling and verifications gives us?  I'd always thought it's about
verifying that resulting history would be possible for a non-RCU
pathwalk with the right timings.  What am I missing?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsNRsgOl04r/RCNe%40ZenIV.
