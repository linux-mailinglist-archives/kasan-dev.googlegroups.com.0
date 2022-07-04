Return-Path: <kasan-dev+bncBC42V7FQ3YARBW7CROLAMGQE2L3IKMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f63.google.com (mail-lf1-f63.google.com [209.85.167.63])
	by mail.lfdr.de (Postfix) with ESMTPS id F243E5657E6
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 15:55:39 +0200 (CEST)
Received: by mail-lf1-f63.google.com with SMTP id f29-20020a19dc5d000000b004811c8d1918sf3055779lfj.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 06:55:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656942939; cv=pass;
        d=google.com; s=arc-20160816;
        b=ELW64eRY+6tMfaRWnkEIb0/b6MNH1eAGsuy/2bt15au63JJ7KN+eMuzi3E4Ols+9Nx
         vSjGsZT4VgZgvkPYCrXw4fNzOsutaqMzj9hHgH+Tpiglft1t13axIyOHeHbXWT1RZYpW
         +DRbKINp2D9FUFUMJEO/jNslL5vwPXVSu+ShQBQ2MlE6PwEpf9W1R+wN9UhhEKOL7zvm
         iva2zGYpCW0QwLt15GIQpmJl//OrLkvmIuPmcHOXRAcIs3X8bcg40Q3cCFRsMNWC80HG
         52E+Uu1Axja8ZeHJvhZpGqi2T7yE6BAe13vZLHVus38WH/QxyTPepIXpC+wW25uBXZ62
         CzbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=aIVTkuTkgjzFNa+KdFWswFwV8vqGsBA1rhYAYJmMfak=;
        b=Uaqyo/OKfZ4bq0YfGjOu7S4AEXmU4hNw9VUjE0HpAtrJ0/xVmDBOQksrI5LVx0k7TZ
         5KN30QLxkulEE/e8XlX4pq5klb9NzmLaQQNQ/KFqNCeF8TuMM0trVbWfIdhFxFEOUbMl
         2Lg/fceK6EXtEz3QnHSA3cMJgsqPDaEVOnMpgHTdb0yEsvWfogbqLuRyPUnDjAMsknFG
         jg5aJqk56DXCbj8Ru2TsnzL2/TaJq5agGtfIhD4MGDGo24Vt7G5i0zKmL9Rbxz/BBxKo
         nOUYBXZAwryfm4cyXcX5icwrHYyXmLPx1rkjYYkAUIZ+YEO315VsHirwl1JcISsHzfAl
         r4xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=fGvBCBUU;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aIVTkuTkgjzFNa+KdFWswFwV8vqGsBA1rhYAYJmMfak=;
        b=Ql07ae2io+vOE176YazszArrmJ5D0cdcxox/BijHZKjy2sewOUcXCM5NHcPZz3NhkN
         rpcUVDsYJueN9h8+xWzJCha98/QXnAWQZAHTZ9cadjY4VNnFDqTyrV3bMIpP23gevnyG
         7rNsHLqxo7pHDAutlM2AKBQ2mzS4ZzW6l9hBnkAThdcUIr+DWkKk/wy0ad7fFZtJHEwL
         JQM38eXAggXqJHHBIaEHGR3QQ+ZcGgXIW6recfIgAohxEwbCAcgiw2iBE0zmKfRmMpM/
         JzBJntS4DyHScQTbLwFz7wGOP9Ga2X1QKPm/EeVkO0syUISwbXesS+sGnH068IWC7Bxb
         Py+g==
X-Gm-Message-State: AJIora++/FigOi+voM0cLtoVVqe+/8vCJo+ozo/zoRXwS7y8+y/YxlRt
	jl+w5F89a27bxGTeoxm9oRk=
X-Google-Smtp-Source: AGRyM1s+SStq3F7UZptH9oJskKk26D9yb5Mf0YQbnv1RSNPvnBCO5/78gS7wktkfLSXVZZfPHvQZ8Q==
X-Received: by 2002:a2e:3511:0:b0:25a:9d92:3235 with SMTP id z17-20020a2e3511000000b0025a9d923235mr17332184ljz.311.1656942939295;
        Mon, 04 Jul 2022 06:55:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls629472lfn.2.gmail;
 Mon, 04 Jul 2022 06:55:37 -0700 (PDT)
X-Received: by 2002:a05:6512:ba6:b0:47f:8c91:b33d with SMTP id b38-20020a0565120ba600b0047f8c91b33dmr18151557lfv.104.1656942937796;
        Mon, 04 Jul 2022 06:55:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656942937; cv=none;
        d=google.com; s=arc-20160816;
        b=BF2oxiim9BD346EkCd3s5AaLYpPuG/QeALI+NJH96kopDoXbuPtQcg8jy61zBMvs7V
         4nIkAIb2ESV372NSYl/zAeQCeVj2+5WHSh9snPU3ywN3PjdL8BA5WoWh/Z/F2oGid9he
         6Ld0TZpvrB00wnJIsVQkAu2sKn8SKU+wckCki/ScBBWgiKsVCQuW7nQR8cBNB4n5u1G5
         wKoFGb+S7BgpvrSjKft+oDL5Pbi3BHm6YW73lGTP4bWVm/it60IRGcMFwbtBelFdVv/l
         fRyNSyW+yTAZysMf+bE4ohLIT3pMxr+CzXnguIL4NfZeZEbKr6Np1dvJ2TUl8a3kAPi5
         DPOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=sFBRrsK/nUCO/qpurgOa37xWDf0Rw4TWhvCcPDzVFrw=;
        b=Q0HzE9HaIyR1vnIPecDZXqURbWyZpQPYjCGubO+zkiev1jR4CHybZLxkLxM+7SiJ0Z
         Pc8m0faiPtPpcsYzKrOZIJWCLWv/bbNta83M7WHb0/cYUI8UYvrwEqcOy+KHF0mzJT32
         00bKR5neR5AVS8oOf+AVWH3Wvb1T14MiSzP/SODA97X1IchU05ZwN7nOfziBNCbTe24V
         vLpzErVXdN3yQEPcwKhoOBUMhCLP+T1ORSj3uFCA67ynC9uUQVfUSM+HnXoFGHnah6lM
         kEfkjZe4Ofv/zqRFScLFtIYbeO/dnUGE/tiJWzGY9XOPrd7gQzlnJBQkyZVA6Gsf/hTD
         nW9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=fGvBCBUU;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id k27-20020a2ea27b000000b0025d2c310ccesi15915ljm.2.2022.07.04.06.55.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 06:55:36 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8MXa-0081o6-IG;
	Mon, 04 Jul 2022 13:55:06 +0000
Date: Mon, 4 Jul 2022 14:55:06 +0100
From: Al Viro <viro@zeniv.linux.org.uk>
To: Alexander Potapenko <glider@google.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>,
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
Message-ID: <YsLxOkApqKPQ8Bep@ZenIV>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV>
 <CAG_fn=V_vDVFNSJTOErNhzk7n=GRjZ_6U6Z=M-Jdmi=ekbS5+g@mail.gmail.com>
 <YsLuoFtki01gbmYB@ZenIV>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YsLuoFtki01gbmYB@ZenIV>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=fGvBCBUU;
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

On Mon, Jul 04, 2022 at 02:44:00PM +0100, Al Viro wrote:
> On Mon, Jul 04, 2022 at 10:20:53AM +0200, Alexander Potapenko wrote:
> 
> > What makes you think they are false positives? Is the scenario I
> > described above:
> > 
> > """
> > In particular, if the call to lookup_fast() in walk_component()
> > returns NULL, and lookup_slow() returns a valid dentry, then the
> > `seq` and `inode` will remain uninitialized until the call to
> > step_into()
> > """
> > 
> > impossible?
> 
> Suppose step_into() has been called in non-RCU mode.  The first
> thing it does is
> 	int err = handle_mounts(nd, dentry, &path, &seq);
> 	if (err < 0) 
> 		return ERR_PTR(err);
> 
> And handle_mounts() in non-RCU mode is
> 	path->mnt = nd->path.mnt;
> 	path->dentry = dentry;
> 	if (nd->flags & LOOKUP_RCU) {
> 		[unreachable code]
> 	}
> 	[code not touching seqp]
> 	if (unlikely(ret)) {
> 		[code not touching seqp]
> 	} else {
> 		*seqp = 0; /* out of RCU mode, so the value doesn't matter */
> 	}
> 	return ret;

Make that
 	[code assigning ret a non-negative value and never using seqp]
 	if (unlikely(ret)) {
 		[code never using seqp or ret]
 	} else {
 		*seqp = 0; /* out of RCU mode, so the value doesn't matter */
 	}
 	return ret;

so if (err < 0) in the caller is equivalent to if (err).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsLxOkApqKPQ8Bep%40ZenIV.
