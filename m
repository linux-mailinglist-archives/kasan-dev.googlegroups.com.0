Return-Path: <kasan-dev+bncBC42V7FQ3YARBUO5ROLAMGQECQYI7HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-f55.google.com (mail-wm1-f55.google.com [209.85.128.55])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BC6656579D
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 15:44:50 +0200 (CEST)
Received: by mail-wm1-f55.google.com with SMTP id k5-20020a05600c0b4500b003941ca130f9sf4131531wmr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 06:44:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656942290; cv=pass;
        d=google.com; s=arc-20160816;
        b=KJ5E3z1Uic46V0xMFfm7MldmDBEON6BSYmUVbqGvJa8bizTykJJmzUQGMao+Z/kmJv
         tlvYsMV86uWYl6evZPGHh5V/Xe8O7YIyAjFg3AL/Pk5p7PFuaB2yaXOoK33auVvudlYE
         A9LmEHEcWVEqO5nE6BSJzfBrNZQTeZAy9y/Gnf3REVGCVsYqHjV2hnFSSZcszgoEmE4q
         3IqgkasVRciBm1Se545EiOoAPRP0SgVjmzF15Wl8Pp6F7rKdADkMnSrDr/0ACH4y0CXs
         p+SShTf5ns3tpN8twYp2jUpZIFsv/49GDSISPXfy+ThhP7ZSoFga6JO9HkAAoY71nnzM
         zZoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=EtHaWADuUcs6jX9RW1gntyCG0FEv44EdKGU0sJeNX2g=;
        b=Ky0qukjJDJ5XBGUI0OQmnqh0j8sjtJ0L09hAdvDj/Coo5zKMt1awQkKXApVTysUlxy
         qC0epTSCPYIQ6RAYE/JJPzXtOEF3Ar+WLl4Eamun+bVwET66daBP/BwD8s0oNgklOEcS
         ciyRN1sTdxKv9u3sQodmufM9ss3RsjykifCn44gmdsU8o3MtJgCTchyMqWpW9Zl1/3IS
         ZIxLj6GeM0dRR4JuD6d1VOxkjB+s8ixkDzYMWYpWYwQtU27G0E07Vl8VuQ88jKAn0ZD/
         ebdUViCDnLMntiqmDm7eqdBbnHlwKI5h0U0vlVldLGyJN1+PxygRm+Ik9biaeFzmlCV1
         /XUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b="nQ/NIdPX";
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EtHaWADuUcs6jX9RW1gntyCG0FEv44EdKGU0sJeNX2g=;
        b=AtWXoFBN7l5jp0t4sdbwktyYsGWA+Vs+Zx71jQQcSL/qCfC2+/pWRhy0pLQnqrZzhU
         HCxnhA8irrV5UpiiySrYApePsTHfcFQWF2l/yyQ1Zq4/UpBP2gui5UPpxmHISxs79qGW
         HdJxjJefwt6wkb9Ug6JDicjaxLyd+oCb3zQmA6gxRgyH60EgKwxZu51LrVRIUAzI02KE
         UpykQpI72kNnTv3UiBvTI9y1pzVFFosiIdEBDRy2AolzH72DNy3ajzYvZYbRX+yBoAXY
         AKyvM53Ry9fp4F97vUPIVk1yAxNaD3esBr76tKduLCgMB0UbFNCINmK+J/Jaj/Kozonu
         zy6A==
X-Gm-Message-State: AJIora/bZSxQWO/j+wv9bZNAJWjJByJEMCkAuRzW3wxP2Pik7dQg0KMh
	L18WqIW/I9czPcSDJRdnXXE=
X-Google-Smtp-Source: AGRyM1u7LlFVGZKCUTX9avxDc22+p2KA8RcXf+iNpYE9cIEnPd0g3DjMub6RgSxJS0g+/umpF4AKgg==
X-Received: by 2002:a05:600c:2651:b0:3a0:4624:b781 with SMTP id 17-20020a05600c265100b003a04624b781mr31937034wmy.15.1656942289803;
        Mon, 04 Jul 2022 06:44:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b17:b0:3a0:2da0:3609 with SMTP id
 m23-20020a05600c3b1700b003a02da03609ls7196916wms.1.gmail; Mon, 04 Jul 2022
 06:44:48 -0700 (PDT)
X-Received: by 2002:a05:600c:3c8a:b0:3a0:4ad8:d3c4 with SMTP id bg10-20020a05600c3c8a00b003a04ad8d3c4mr33224956wmb.43.1656942288613;
        Mon, 04 Jul 2022 06:44:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656942288; cv=none;
        d=google.com; s=arc-20160816;
        b=PdS5bdutMGYlZ7vmMD7wxoy0fuqj98Tz8KsC4LXWMWyFAjI6jtGycrGARC3CScQBII
         dkxznwGhP0BCnB+KBYZPTarzPoK6nSCNSyY4EjJL3VEKlzypN5C4ngi1Z8Z97QYF5eTF
         DM6WDJpZAGBlQemvXKfP88HjIYIIU5ElpEzzROHnARgCXoGvFavagVpugTDDNnjVoU2I
         j88ehcCNc2CSOk+pwf24ozVgvduK+K/YMXkDxcJGtRnFp59CYM74QXZyhCLoGTkAmvS0
         uKp/PBYrDsAmQQODKRP4VqtYDFKHsS4bzVFCcBxZ6ocBlhthL+JgaDTgVhpobLKfozTj
         u1Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=L6wSaDv21i8IBXuOCFtPFoc5AHwc9orKajt9IjPXWew=;
        b=gQQS81sQ1SSxxrXV6J/aWTZ9iRthziGQ7Ek1iOTL1ZJjEqr86lfB9fFPNPfwof5gUB
         zewEMTGc3N7SXQ4ndzp6cEPPdOe+Y98pHHtYDzzvmH72TfKmsUCfOP+EzPO7P600ocxN
         6lAT74dGQuslUSeZ4x7+IpQ1BlLa8PVW4uLtpk6MGsS5VWiIsirwHwlLfe12s7GRlGhj
         X4ArJPLOFfVJ/iWJfMhmWI9GbKiw28apcxLXgMQ45+cvXLXsqV+8OA6JjGQPepEhQeqR
         F9ZBDHBn12/UvWe5EyeAN+K/2ZVNixZp8KwYqF+P8WHuNb8gieHpYYkRAZQKZ1u5sg4R
         ql/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b="nQ/NIdPX";
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id ba28-20020a0560001c1c00b0021d2e06d2absi522936wrb.3.2022.07.04.06.44.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 06:44:48 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8MMq-0081dA-Ie;
	Mon, 04 Jul 2022 13:44:00 +0000
Date: Mon, 4 Jul 2022 14:44:00 +0100
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
Message-ID: <YsLuoFtki01gbmYB@ZenIV>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV>
 <CAG_fn=V_vDVFNSJTOErNhzk7n=GRjZ_6U6Z=M-Jdmi=ekbS5+g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=V_vDVFNSJTOErNhzk7n=GRjZ_6U6Z=M-Jdmi=ekbS5+g@mail.gmail.com>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b="nQ/NIdPX";
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

On Mon, Jul 04, 2022 at 10:20:53AM +0200, Alexander Potapenko wrote:

> What makes you think they are false positives? Is the scenario I
> described above:
> 
> """
> In particular, if the call to lookup_fast() in walk_component()
> returns NULL, and lookup_slow() returns a valid dentry, then the
> `seq` and `inode` will remain uninitialized until the call to
> step_into()
> """
> 
> impossible?

Suppose step_into() has been called in non-RCU mode.  The first
thing it does is
	int err = handle_mounts(nd, dentry, &path, &seq);
	if (err < 0) 
		return ERR_PTR(err);

And handle_mounts() in non-RCU mode is
	path->mnt = nd->path.mnt;
	path->dentry = dentry;
	if (nd->flags & LOOKUP_RCU) {
		[unreachable code]
	}
	[code not touching seqp]
	if (unlikely(ret)) {
		[code not touching seqp]
	} else {
		*seqp = 0; /* out of RCU mode, so the value doesn't matter */
	}
	return ret;

In other words, the value seq argument of step_into() used to have ends up
being never fetched and, in case step_into() gets past that if (err < 0)
that value is replaced with zero before any further accesses.

So it's a false positive; yes, strictly speaking compiler is allowd
to do anything whatsoever if it manages to prove that the value is
uninitialized.  Realistically, though, especially since unsigned int
is not allowed any trapping representations...

If you want an test stripped of VFS specifics, consider this:

int g(int n, _Bool flag)
{
	if (!flag)
		n = 0;
	return n + 1;
}

int f(int n, _Bool flag)
{
	int x;

	if (flag)
		x = n + 2;
	return g(x, flag);
}

Do your tools trigger on it?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsLuoFtki01gbmYB%40ZenIV.
