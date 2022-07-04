Return-Path: <kasan-dev+bncBC42V7FQ3YARBCHTRSLAMGQESZWVO4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-f60.google.com (mail-ed1-f60.google.com [209.85.208.60])
	by mail.lfdr.de (Postfix) with ESMTPS id F120F565DB5
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 21:03:36 +0200 (CEST)
Received: by mail-ed1-f60.google.com with SMTP id s1-20020a056402520100b00439658fad14sf7832762edd.20
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 12:03:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656961416; cv=pass;
        d=google.com; s=arc-20160816;
        b=hBgn1AFM29zDMhJWUv3fllTjERjedcpCPUck6ndxC9pbdQ9hJtDyk+0V6/2GWqX6hy
         Rz3O6lw9FzYRQyM4XN2cadC44Dye4Eo39FiYXdU80na0Gg//tDOniXp+7VT3SpiO4dw+
         c9/X/0ec08lJqiJscaYD8gPhnGoq79UD0wEF0gln+kjruV83Q6QtfqCpqRJs3TbiX+Qx
         J1O2AljtW5DfILxJlcnCkEyOEfgOyVm+v5XqH0ee77l0sLUNduognEKydTaOHagxU/9p
         LgGVNmAtYqXtc/eAjLWWNRH78rxsUgZhXTdlzraOZNAqHymugnt43nVlTW0VE73YGBJZ
         xYwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=50gwjjBJuJjpc+YxmyrafPOnSHMN5X0FpOfyTG1nrXQ=;
        b=L+1PS6hZuM0CGk2Eg3863HMoTYhAY5OTefzItOc2ujGQjZwhCW9PRHKh/+MRtc2NJy
         5ls1ibnw5AzUwed18dt1Sg79MUfceHQ8vehGKNjhpktNkaFi9yutgxgdVUz5Ctp05BkQ
         rmAIJmJVI/EWuyUEev8SXQwiwFzw5yapmfN7JKzjZYSq3Jf3fk7nmIDVRe6ettFVAHBk
         /6yFv4in1hwb8i8sUZivUw7RXve+zVIRoaC0cWw5qFGBM8d24Sm5OnVlM31+TbzKQc3V
         RwXWkqw1ZKbpUE28L4W2FwOPpPjSIzyOsvrkAhnBfioEcE9h48jKA2PdzB+B+Ya6rXk8
         AEwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=gION5JVU;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=50gwjjBJuJjpc+YxmyrafPOnSHMN5X0FpOfyTG1nrXQ=;
        b=PQo9AP2kus9V/5xHabi++gdcjVj00T8He+BONvfaR/XVDbQKVM7n3twjnWaJ+o4L47
         kurRkgv9dddVG0hiq0AzNHVaK/A9kuHt42DOlfFKKWF9acSusBKmtpGrWphBpGPCO2y5
         cZigeuITcHJ7B1biD0+4TMOdiEynSdTxK8kF8BXq4XE7AJbzI9MjQK5ypxlVBVXOl4+Y
         RTYrlBPA1+xnIbFNr1DH26yhRTB16IXyUI6bXP4jRKp4m1v3ftN2oEsvWua1VrY9OjiT
         mQmiG40C7VS5Ybj8cWpBAo5RYwjihTG3Q7zLraFfhjEauGGE0hu/qxdCoKOzBsGBE1Ol
         bDVA==
X-Gm-Message-State: AJIora9Fmmaz7st3LoW5usvFjHZ+DKo7Q0NtZuU7mGeIWtx8nNAqqofd
	LqBfkDn4yOzNewvdHEPj8Uw=
X-Google-Smtp-Source: AGRyM1u6ELDc/MmDiXhgN2vT7Kjo2X9PgTv7ZV4lsm3gLp+Xg0nZEoX6l9RGliN7Q9Cy2A4S7gUMIg==
X-Received: by 2002:a17:906:f14b:b0:722:fb06:83a9 with SMTP id gw11-20020a170906f14b00b00722fb0683a9mr31259396ejb.473.1656961416590;
        Mon, 04 Jul 2022 12:03:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:95c1:b0:6ff:45d:c05d with SMTP id
 n1-20020a17090695c100b006ff045dc05dls7746476ejy.5.gmail; Mon, 04 Jul 2022
 12:03:35 -0700 (PDT)
X-Received: by 2002:a17:907:7678:b0:726:9fca:8106 with SMTP id kk24-20020a170907767800b007269fca8106mr30883780ejc.640.1656961415343;
        Mon, 04 Jul 2022 12:03:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656961415; cv=none;
        d=google.com; s=arc-20160816;
        b=WGPLdOmG6VBkzEFUG2yZtxYi3FOtgqGDjLchrWAa7ciRDp02S6RJhPLJuRNQLLONNW
         TJe94/TD2h02R+/F8uSSWr6DQZNCPrtPJ3rSa4/fjBf+I2V17nmGJTBPSdEwZApKaDau
         21CIG+07/RxHapvIT6ALKRrHTFOyWmacTUaZ6GrgUkYlWfxf1xQMsSoDrrgpfA2Pv7CS
         9K+utJiVMq7debSAkBaOOvd+vN4Bq/fJxWJGsPT48tOq1T015JmnR9Ab+Co/g+x1lTzY
         19iKomtkEA4WfkRZtqjPO7ay1uN58g6gfJWb9EX6l8l3g8Di/U1fPsp7BsnGP1R/BHgQ
         thGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=StWcqGItZutY3CkZqZp4EajG2FBl6ewxUbX21EaiIa0=;
        b=vQM56YJyPfyJSYZb/qyqrQVkWz42QlFunwg4pcwbkXz9G+VWvsqODxPlSligV/nz66
         dpczbDvEk2Kef60NQ9+L3x3YQvC8xo1mHqqVpHcFg9wHoaNO8Twu2BgqeFDdelTV4+YP
         8R7mdo3Ojb9sMuHhVTFEsGLkKL2oBNi6Kz2YlHpGUdZ3NQEx4roY/RNW5Syd47AQtK3L
         1KUrMgzd+jz2ZFm4swdd0Q64UQCNt30tiKgzEacKUNMLYeBg7dZKaiuFeOBawCUgTqJr
         bdkoqQyx20SycC2wo7jbCqH3mBL1uAsjimGnWRyzHtzfKqobeCcdrwcvv4Y97yq5qphK
         sM0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=gION5JVU;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id s19-20020aa7c553000000b0043a2a36df0asi138135edr.1.2022.07.04.12.03.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 12:03:35 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8RLQ-0086lx-NV;
	Mon, 04 Jul 2022 19:02:52 +0000
Date: Mon, 4 Jul 2022 20:02:52 +0100
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
Message-ID: <YsM5XHy4RZUDF8cR@ZenIV>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV>
 <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=gION5JVU;
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

On Mon, Jul 04, 2022 at 10:36:05AM -0700, Linus Torvalds wrote:

> For example, in __follow_mount_rcu(), when we jump to a new mount
> point, and that sequence has
> 
>                 *seqp = read_seqcount_begin(&dentry->d_seq);
> 
> to reset the sequence number to the new path we jumped into.
> 
> But I don't actually see what checks the previous sequence number in
> that path. We just reset it to the new one.

Theoretically it could be a problem.  We have /mnt/foo/bar and
/mnt/baz/bar.  Something's mounted on /mnt/foo, hiding /mnt/foo/bar.
We start a pathwalk for /mnt/baz/bar,
someone umounts /mnt/foo and swaps /mnt/foo to /mnt/baz before
we get there.  We are doomed to get -ECHILD from an attempt to
legitimize in the end, no matter what.  However, we might get
a hard error (-ENOENT, for example) before that, if we pick up
the old mount that used to be on top of /mnt/foo (now /mnt/baz)
and had been detached before the damn thing had become /mnt/baz
and notice that there's no "bar" in its root.

It used to be impossible (rename would've failed if the target had
been non-empty and had we managed to empty it first, well, there's
your point when -ENOENT would've been accurate).  With exchange...
Yes, it's a possible race.

Might need to add
                                if (read_seqretry(&mount_lock, nd->m_seq))
					return false;
in there.  And yes, it's a nice demonstration of how subtle and
brittle RCU pathwalk is - nobody noticed this bit of fun back when
RENAME_EXCHANGE had been added...  It got a lot more readable these
days, but...

> For __follow_mount_rcu it looks like validating the previous sequence
> number is left to the caller, which then does try_to_unlazy_next().

Not really - the caller goes there only if we have __follow_mount_rcu()
say "it's too tricky for me, get out of RCU mode and deal with it
there".

Anyway, I've thrown a mount_lock check in there, running xfstests to
see how it goes...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsM5XHy4RZUDF8cR%40ZenIV.
