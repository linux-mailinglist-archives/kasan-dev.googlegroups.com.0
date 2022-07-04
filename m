Return-Path: <kasan-dev+bncBC42V7FQ3YARBTPIRWLAMGQEZDFRLLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-f64.google.com (mail-wm1-f64.google.com [209.85.128.64])
	by mail.lfdr.de (Postfix) with ESMTPS id 025E3565F98
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 01:14:22 +0200 (CEST)
Received: by mail-wm1-f64.google.com with SMTP id t20-20020a1c7714000000b003a032360873sf8027587wmi.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 16:14:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656976461; cv=pass;
        d=google.com; s=arc-20160816;
        b=s7u2cqla6LrfuJbTF9+b3h9xlUFvgUqbmHFYJubgKYM6F3vH+mCQL0B9RxZZfzIM/z
         LMSTKMbE7q63u6ybadIJMW+7MLs9DJFIylqeSbobbMqMLcPws8rZybtQY2BXGtIfkAqL
         OhYZU+vD3Lnn+L7GlKV1HfTWcvTPaoE0FiodzAe/Y7pELK5POhd4Shr402DCUpLr5rBS
         jgswQTtdp+YugWZK2HtSvbHLvI0o95nNLB/phygRflNmSZ/GwZHUDnv0NEgcV79gI4lg
         +5k5Pgi2/UPuAVslej3V7c6CfI4sVV4ACqdK8icqGeED8jZ57j5yXim8dHMPCOXFwXcc
         LquA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=s1r/CrO395ICdUzomlqioTpP1Kpfn8oiXa4Gr1i0zGI=;
        b=EhdiVmaHguwk9tXU6FPIMKoFiPwCJgVT1B3MLKM7ln0JA9RfS6ScLQm4bwVRScEInd
         Zg6QlCv7rNNIvy6pjkt4R3NUkjtTWQSWaX3NLps5Zwopz3xJhpEWR2Re1aZg9x6LOedC
         sq0ZknIzl9BXYNIT9cuulb2TwhlP7L8L7OYY9mcqe3rWXERB+noH9LGqf5SZ2B50P57Y
         v1fnCEBxdAalNnwgbWAcEJM4P8iu4gjoNaaSbscbm3dpvKiQ4EI8b1V7Ggnr8QUwW/QR
         2kjBtz6VXLOM5K8mcr5fbgw7A0LGytVnnDR0ZuhsvOe9K3zHfM40REdRzhR0Mwa0FeSl
         6ojg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=icrM6bJz;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=s1r/CrO395ICdUzomlqioTpP1Kpfn8oiXa4Gr1i0zGI=;
        b=E5UX5KBBoJY6ES4dOZGKfTpuKbu6k/n+vSCZ8GvK/l+HRiXObZ130a36BEE7egZogr
         n3mssWAZgXkGwi9YFHCWE5pTEdvq9rhorVS7ywx9E+CUngxq5YDcdxSBnKPyDxaOmllF
         OPJ8no/h9xhbG5FMrDqo3iztM88zbJKMo12N111SBPxu5MoW9QWJP1K3kRLrqyeqsjm0
         beaBJQcBXggXC9axc8/GYq2JDOvV3g2rjYni7RZ3e/42wtcXx87Z3eVLrz4QS0Qss22o
         ZeERGwxxvlD0+D6/l70NkCiwAfCVKZsKjHZotWndDoNuEW6WKZJP46GmGFuY9PDB3DoR
         T27g==
X-Gm-Message-State: AJIora+3IVUc74UlNIc+tZLUNz1ZFPfCmzquA7RR8mdf6drUffe4d7/1
	EqxtE26SyjHE7z7SdAohROk=
X-Google-Smtp-Source: AGRyM1s+kkOIqaipU82ESNPYLmzwEv9Esz1EoEcYeuCTEvSjRrreEfknMIx/viRnjD5zH8y0BGoCnQ==
X-Received: by 2002:a05:600c:3d96:b0:3a1:8681:cc80 with SMTP id bi22-20020a05600c3d9600b003a18681cc80mr26286328wmb.192.1656976461640;
        Mon, 04 Jul 2022 16:14:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2204:b0:3a0:4611:be94 with SMTP id
 z4-20020a05600c220400b003a04611be94ls7790073wml.3.gmail; Mon, 04 Jul 2022
 16:14:20 -0700 (PDT)
X-Received: by 2002:a7b:c381:0:b0:3a2:aef9:8df4 with SMTP id s1-20020a7bc381000000b003a2aef98df4mr6574529wmj.7.1656976460435;
        Mon, 04 Jul 2022 16:14:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656976460; cv=none;
        d=google.com; s=arc-20160816;
        b=J5GlJroT7FpjPGpnB5eaE1mptq1WNE2ct0NXs07nLfIIhKD3EV6MwC1pUjc3j6ii6A
         fBKzmpnUMenprYRv/3PdQRXczdeGvsSSu3CQdcPI7XuPeKT+2eZ3WkDjoNZM9vpTvFcj
         3KTTjQOvj+40RgSODBtGm7RhPjmv+PvscEwPGdhCGzAa6wel56eR90xA+txmnBzz0W6T
         QHOSofJQEJi5C6l6T9Xi67u7EdV9NzfTqm1FEhs+Ule0xhYw8brZxrJ3DsSxoH1HrrSu
         bkQS3Acu48z/YvKgMHMgAoeoHVRveUaYunhdqBvXyQi8lOjOZEtsJ0StvS1nPWMh0Mw1
         hF4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QDUaP7j+G+WPLXwk1QBlWXofxxUo5BaNc7z5+9RX4yU=;
        b=nuL4aVdnSz9YL37mYpGA50HgRmUOeat/pyKa7ctUFMhi14W88TCfXNee7g64JxMARj
         sBWyx87OKopyf/waXACo7Xgqnp7YWnNGEClyeA0297Uqac3Gzbw7jFezyPj/t33DqpEo
         MlJYQxRXsSMTH1Mli6mcRLH5iz2hhMgenattkRFhq9/t0fWSm87oYDXcY2HOtDg5Awtw
         JlXsc+GQtf3kK0cykb/dIeYStLvtIpYNFq/DjYE4HkvNfummD1sG32ui6xKFDkbYsy8E
         PqFbUcKe8fwDB1yEhjFyTrk2xyRWlLc/oGtCF9CAlk5jBDlxye0MBH+S8jV/KoH/F6Bf
         T0CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=icrM6bJz;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id co18-20020a0560000a1200b0021d649cb04fsi261478wrb.5.2022.07.04.16.14.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 16:14:20 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8VFx-008AVO-KU;
	Mon, 04 Jul 2022 23:13:29 +0000
Date: Tue, 5 Jul 2022 00:13:29 +0100
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
Subject: [PATCH 1/7] __follow_mount_rcu(): verify that mount_lock remains
 unchanged
Message-ID: <YsN0GURKuaAqXB/e@ZenIV>
References: <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV>
 <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
 <YsM5XHy4RZUDF8cR@ZenIV>
 <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
 <YsNFoH0+N+KCt5kg@ZenIV>
 <CAHk-=whp8Npc+vMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA@mail.gmail.com>
 <YsNRsgOl04r/RCNe@ZenIV>
 <CAHk-=wih_JHVPvp1qyW4KNK0ctTc6e+bDj4wdTgNkyND6tuFoQ@mail.gmail.com>
 <YsNVyLxrNRFpufn8@ZenIV>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YsNVyLxrNRFpufn8@ZenIV>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=icrM6bJz;
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

Validate mount_lock seqcount as soon as we cross into mount in RCU
mode.  Sure, ->mnt_root is pinned and will remain so until we
do rcu_read_unlock() anyway, and we will eventually fail to unlazy if
the mount_lock had been touched, but we might run into a hard error
(e.g. -ENOENT) before trying to unlazy.  And it's possible to end
up with RCU pathwalk racing with rename() and umount() in a way
that would fail with -ENOENT while non-RCU pathwalk would've
succeeded with any timings.

Once upon a time we hadn't needed that, but analysis had been subtle,
brittle and went out of window as soon as RENAME_EXCHANGE had been
added.

It's narrow, hard to hit and won't get you anything other than
stray -ENOENT that could be arranged in much easier way with the
same priveleges, but it's a bug all the same.

Cc: stable@kernel.org
X-sky-is-falling: unlikely
Fixes: da1ce0670c14 "vfs: add cross-rename"
Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
---
 fs/namei.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/fs/namei.c b/fs/namei.c
index 1f28d3f463c3..4dbf55b37ec6 100644
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -1505,6 +1505,8 @@ static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
 				 * becoming unpinned.
 				 */
 				flags = dentry->d_flags;
+				if (read_seqretry(&mount_lock, nd->m_seq))
+					return false;
 				continue;
 			}
 			if (read_seqretry(&mount_lock, nd->m_seq))
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsN0GURKuaAqXB/e%40ZenIV.
