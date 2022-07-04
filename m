Return-Path: <kasan-dev+bncBC42V7FQ3YARBTULRWLAMGQEJHTCZNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-f187.google.com (mail-lj1-f187.google.com [209.85.208.187])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C4A8565E2F
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 21:55:59 +0200 (CEST)
Received: by mail-lj1-f187.google.com with SMTP id c13-20020a05651c014d00b0025bb794a55esf2909249ljd.10
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 12:55:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656964559; cv=pass;
        d=google.com; s=arc-20160816;
        b=GbhCNaceJLL2EPOo1m/Ht5K75TkR27B10/M/DSt2BPvZRPKMyNJFHyVpyTIrxbLjsm
         JcrAQeK/btQszday0WFxfZITcErHvBJyl/4LIUs5wKxQXYM9OCGlV3Ry1KBRiconPjao
         pP+eashWaQGmtgBLRMGdp9sWlyj5xEKU0jkaHTlH3iqR48xU5ht6MJ+tII9saP9TeSFd
         c8y0cc2dVf5jGtVc4CydsSAAetTw6SLLvlquljc12RW1iG9zzfUPiA84oaTYpBSQPMKu
         g0PSz/+tFdVGhQS/K94WGVTJbgHA5Avuc03dh9+dRmCJxnTHpf6KkLjZnBdgeThvdopi
         Mhng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=1y3031bn8eGhruld9DnDj6+4VOl4IID8dVISmwkSpys=;
        b=GfC7RxWUvAdnYOKD+ApWTYpoF4QMpWNTROReSoGxN/zx2tb0S/wfM2w3vd46iXUDnw
         LHgIi7OnJkXGpgivHmCvwK5c4BfHqrYaAVb/TGQ6WtFpJ5lyrpkadwX7rkwa1SVSk8lQ
         yE2g7irbFQvmUwl7Fpckk2jPe3e+xE5bJSdOp4vtSsGxJN14ct0dn4t/TT2hZz03xCgs
         Ug9Q26kny3phiccOL0tvy+/+CHjEzT6oHNSAN2svEqPQnb1o2KRaYLXdAOyyey3WW007
         6t88yl7izA7eyW13pnY9wi0xBodFtWVYWuArwQa1JDGGnAvr9as8z3A111dbSt8u1NZK
         PBTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b="Lcb8/maf";
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1y3031bn8eGhruld9DnDj6+4VOl4IID8dVISmwkSpys=;
        b=GzkAMkrR1kOmcCy58AQUIhRiP1YoDxs6g/VrGy5Rsn15TFHnZaXZOmYAa9OKMu1WmY
         zT80thoNSQfjhPIHf/IEENEge+hG/MflPR4m8sWDICZqZUOYuN1WjmER9SAfoZ2CIjiN
         ZFd9YPFYbNTbw93DAowluo2Vxn38JnYzVeny7I0cwDBaUVW5O6ULGOWkVfKUic40PmP3
         i963XJBuQBLJS64WYzeu2193x1stqofciver1YeYrnu38wLG0gBDxZbH/K7tgmOZ7oSj
         6KZ3FMSiS4RikEAtHkIVrxdUsajf95t/3CfP4pXIliEaxbCq3a8THsP7Fr0yRHNZFQkO
         t8iw==
X-Gm-Message-State: AJIora8egIJLkJJZ2T17Zx5bbjZbDM0nLStAjiXg7PBoFdYoauS5aQTe
	sXQ1Hudaj6ar6fx4YJ0t8Co=
X-Google-Smtp-Source: AGRyM1s3jlA9P+QJtqpIPjnsWo5sBx7HxJe038L9Uve2p4WYLVNuTcR7WsVZv3glEijw18A5oh7Dfw==
X-Received: by 2002:a2e:b8ca:0:b0:25d:3043:cc4f with SMTP id s10-20020a2eb8ca000000b0025d3043cc4fmr313142ljp.483.1656964558801;
        Mon, 04 Jul 2022 12:55:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls8594lfn.2.gmail;
 Mon, 04 Jul 2022 12:55:57 -0700 (PDT)
X-Received: by 2002:a05:6512:3fa7:b0:47f:7387:926c with SMTP id x39-20020a0565123fa700b0047f7387926cmr19430366lfa.98.1656964557411;
        Mon, 04 Jul 2022 12:55:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656964557; cv=none;
        d=google.com; s=arc-20160816;
        b=xkG6VekjWrilJZEiG3+1q00t+c4pBvnXNqk4roiZwbAzunFU+/DT4dFL+6sR9wwgpb
         TAQo5OLwHuLI/hdr2o5qbVhdgnwP7p/IwSobSAGbsxGEXRMiuQtv2PDue5BRhURNLJt3
         4gOHyCbF7zQOQlRDtO/Iie9huNiX97AetXseqfUtFbg5Jsv0U2yX7bWAGCJLgNGSCGoz
         Ero3sJ7BDv45MCVHn8OsDxH1rz0aEPDSrz83v2xZGia5we66NqGvTa+YMB/NzZPwV6fM
         GBnmrYKmQ4c0t7Yla/r78235z6o7Bg1MWD5oNCs4x/S+55ROVgg8eooC2wuPBGyN0TDs
         olAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=1MlVvLG41NeVJL2nvZkPrUdGWixdJlckw5dTfoQTefk=;
        b=KAE7e8+WkbWGObu3JgZbCFXcoqLH3Fm8af8befqq9fD0hP2l+qv6k+8+0gReHRjvmT
         ye7sXAtD5wq9tQU4ilca5LMb237ckA3S/u2wYXxO4qyjY0iETyxx1qaM/mpNVx28J3Mb
         ufaoO5WEsEUDYEmuIGAHkXKZxD8lPdLiQZOsS3DxLjJoRneucFrE8mU1cwCdFyPE9Qye
         abHkJhUvgq6mnhFhjAf1Iha7Q9epQcZhc9zaKWtQKkGlc9dQCsXsqfFleQVQjWjV+1hY
         4HnYVnvz/Jdssj831TwbSC4EySeIBKmyDXCSDBKCqgSBjuLKhiGbidc7B8OZXj5QkkcC
         NDPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b="Lcb8/maf";
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id u17-20020a197911000000b0047fae47ce32si1216161lfc.9.2022.07.04.12.55.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 12:55:56 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8SA4-0087lj-68;
	Mon, 04 Jul 2022 19:55:12 +0000
Date: Mon, 4 Jul 2022 20:55:12 +0100
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
Message-ID: <YsNFoH0+N+KCt5kg@ZenIV>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV>
 <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
 <YsM5XHy4RZUDF8cR@ZenIV>
 <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b="Lcb8/maf";
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

On Mon, Jul 04, 2022 at 12:16:24PM -0700, Linus Torvalds wrote:
> On Mon, Jul 4, 2022 at 12:03 PM Al Viro <viro@zeniv.linux.org.uk> wrote:
> >
> > Anyway, I've thrown a mount_lock check in there, running xfstests to
> > see how it goes...
> 
> So my reaction had been that it would be good to just do something like this:
> 
>   diff --git a/fs/namei.c b/fs/namei.c
>   index 1f28d3f463c3..25c4bcc91142 100644
>   --- a/fs/namei.c
>   +++ b/fs/namei.c
>   @@ -1493,11 +1493,18 @@ static bool __follow_mount_rcu(struct n...
>       if (flags & DCACHE_MOUNTED) {
>           struct mount *mounted = __lookup_mnt(path->mnt, dentry);
>           if (mounted) {
>   +           struct dentry *old_dentry = dentry;
>   +           unsigned old_seq = *seqp;
>   +
>               path->mnt = &mounted->mnt;
>               dentry = path->dentry = mounted->mnt.mnt_root;
>               nd->state |= ND_JUMPED;
>               *seqp = read_seqcount_begin(&dentry->d_seq);
>               *inode = dentry->d_inode;
>   +
>   +           if (read_seqcount_retry(&old_dentry->d_seq, old_seq))
>   +               return false;
>   +
>               /*
>                * We don't need to re-check ->d_seq after this
>                * ->d_inode read - there will be an RCU delay
> 
> but the above is just whitespace-damaged random monkey-scribbling by
> yours truly.
> 
> More like a "shouldn't we do something like this" than a serious
> patch, in other words.
> 
> IOW, it has *NOT* had a lot of real thought behind it. Purely a
> "shouldn't we always clearly check the old sequence number after we've
> picked up the new one?"

You are checking the wrong thing here.  It's really about mount_lock -
->d_seq is *not* bumped when we or attach in some namespace.  If there's
a mismatch, RCU pathwalk is doomed anyway (it'll fail any form of unlazy)
and we might as well bugger off.  If it *does* match, we know that both
mountpoint and root had been pinned since before the pathwalk, remain
pinned as of that check and had a mount connecting them all along.
IOW, if we could have arrived to this dentry at any point, we would have
gotten that dentry as the next step.

We sample into nd->m_seq in path_init() and we want it to stay unchanged
all along.  If it does, all mountpoints and roots we observe are pinned
and their association with each other is stable.

It's not dentry -> dentry, it's dentry -> mount -> dentry.  The following
would've been safe:

	find mountpoint
	sample ->d_seq
	verify whatever had lead us to mountpoint

	sample mount_lock
	find mount
	verify mountpoint's ->d_seq

	find root of mounted
	sample its ->d_seq
	verify mount_lock

Correct?  Now, note that the last step done against the value we'd sampled
in path_init() guarantees that mount hash had not changed through all of
that.  Which is to say, we can pretend that we'd found mount before ->d_seq
of mountpoint might've changed, leaving us with

	find mountpoint
	sample ->d_seq
	verify whatever had lead us to mountpoint
	find mount
	find root of mounted
	sample its ->d_seq
	verify mount_lock

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsNFoH0%2BN%2BKCt5kg%40ZenIV.
