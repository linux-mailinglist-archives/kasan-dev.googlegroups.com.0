Return-Path: <kasan-dev+bncBCLI747UVAFRB7FO7OMQMGQEVFPMADY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id D2C1A5F67E7
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 15:26:21 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id 7-20020a056a00070700b0056264748f0fsf1169025pfl.21
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 06:26:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665062780; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qgf37CtEsWPmj3VzKmyymoIS/EqLpCzFmMkFTHsDd7Eg7o5yCFRV9sWqcdptGE/o2x
         lse+fVY+NwOP2kVN8dbrs2F6KQzKdi2C5qaPBRlGochM7LOOpSltrU7gy44G5kBPKCk2
         4lW37F8mb2+m1/pvv7g1NuXxFjPo/V1KHt8d16ZFK5SUZbYr6l9svVhFPM2yuYIA7L2+
         5D+bJ+q47Fy1+Gea8RdDzgmj/H+PrxKA+iV3PhFGELQvA7yXyxqKGM1ToQiNwChoPehk
         1FY1j+QT6RPd+UGGcnaVkg/fwNIFPfItYtW+CcqS5XHSqvkDzLIC8Gm8psfB+jfSwxxd
         K2Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=54wE153QUUBzhuqfThDvmo5LGrPVAiSa+cP2HcGha00=;
        b=EB4WysMECd7bpWLmD7B6tNwNHFxs30Ngy2SQK9YS40ZBzMLRHhrg8Lb9Q2yy+npGtB
         Wiu8B6478zE581fM/UFr0OYFd37ONy6RI34RRtlIDmtWASSgoKDvbPL+pXpEHHhMbv6e
         QNgnx/KlKnVGraQPmrngt+n9HDNRVmWhV3ZIQluwGL+C5SCkDDLFFau9m/iw25xIfdzi
         707f6Ghh78nhYNu2MNVpSJdaqROiq4paSeZhuu6/eGQPYT03VmY+4OI8B9Rc0llfksF4
         JGf/hXICmLR66RUnlgXD+00epkDKcgdQZBoB8/BrFtJwl6eg8Mw8WgHYxzGUdxcVlGyj
         Akqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=m0HkubMp;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date;
        bh=54wE153QUUBzhuqfThDvmo5LGrPVAiSa+cP2HcGha00=;
        b=gmzopzMCU+XO27AYRpaceugfFKnz4M17sXusWmYhE/8OKxdQCSlXrM0Q4uWHVLY+//
         3KbHDmrWGd7oVF/K6A5jdXTDwyCrXDvbZmo0MIXUltd6NuE5Sc4py3h4wM8G8e2Ux0L8
         REQ2615XZ0DXkNEobZl1DE4cuC3jMdS4lQXYyw91hst1ZS6OwBSWlHUd3J4oY93dhQll
         lxKj6tpEiuc0lCo+9smV6G7CZzhbBiZMsdy9fo0RHVZBMLc5HkrA1wVUXR8Wlh4bCbw/
         QQfCwb1N1/dLbKpGfRHVkvBmSGrBQ0CeQbrY9GOnsHLaic+L0cwwXWUUwCK94r3nZGD9
         htsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date;
        bh=54wE153QUUBzhuqfThDvmo5LGrPVAiSa+cP2HcGha00=;
        b=1FSdfiR5x9xpCXeR+flTB4t11/rYYQGps6mL67KwFzuxmFoAifWM269pcoOKx28ajM
         Sg6uIqkUOoAiUs68P8cy3eUhOqIOLbx25wyObd2ZCJ0xUhUBW3RJlxPAb7TPXhz0S+69
         Bd3qD+/vfHOaLcSKX4kuIWQ2smO1WHXSLh4BJv/e6csk3fslOK44TNZXBU+rS5j6PFZl
         Gxc+uQ3Hmqr/lO/3K/sglqLDvc+ENnWHOzd0ojqcfH6f1MwNvZiC17bmCWg8SjThbgue
         Yq4Fmn0y0D1Od38qw3HxVDxCRC/jAEGjKBe9v4Er15tM6xTCncFoFjk37+qi4s9hFdTt
         wCsg==
X-Gm-Message-State: ACrzQf3iuvwcT89Xaplrk4BV0UWlbvod+pzz4cj83Sr0Yttesz+8KswQ
	f0LYO9XDTyiiGrmQWmDuqvY=
X-Google-Smtp-Source: AMsMyM4gxxN8+Z2TkDdq92Q/gb3QanMa/45hni0Og3eG3ytmCnRV13cTTEBH0vuatv0Hk7QLm2Nd5A==
X-Received: by 2002:aa7:88d0:0:b0:542:d98d:bf1f with SMTP id k16-20020aa788d0000000b00542d98dbf1fmr4789291pff.78.1665062780177;
        Thu, 06 Oct 2022 06:26:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b90:b0:20a:feca:b873 with SMTP id
 16-20020a17090a0b9000b0020afecab873ls2288629pjr.0.-pod-canary-gmail; Thu, 06
 Oct 2022 06:26:19 -0700 (PDT)
X-Received: by 2002:a17:90b:1b41:b0:20a:f406:2b90 with SMTP id nv1-20020a17090b1b4100b0020af4062b90mr5337927pjb.7.1665062779495;
        Thu, 06 Oct 2022 06:26:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665062779; cv=none;
        d=google.com; s=arc-20160816;
        b=C6ARDGWcMSywIZFApDnH7Bncvomb+1SSwiiWXWeh/fpFjuxoYN7vKFJDRQVOATzXFB
         CLcij9Ji+BZbqAOIgxqQfLrYHd4tYXq6/Vclmb1+k5d9HMxwiFqMfzN9JSh9uazuOQu2
         ccSFHTfkP51fxBWaueFLaKmdG6Aolz5o1qyxXjjZjgUVAI7MkjIXIuRiBe5OYDxiVWSj
         my0S+vL7uNnQ8/gyiXK6Q4IuPr7LE6FRUPSVLL0zT4I1rfFbrXVCZScOYNrpj784VgSm
         oWuD6q3c9vA2k7rxGNtX9JBbO5MV6y8L6+LAP1P8JoL4IQq8o+224c8PXuEJ9t+ACyR5
         L6jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oFCjWqQv2aesuJpqe1Hhx/O5Y2jwoykcxVrUd1V3HAc=;
        b=cP6qIFkgkPgSorVysBPlYeYiv5i76r8R5NGwNG5F45iNrKdH1NIfjK5m35S67Ch11M
         0wlzZoFVbCaglNlS7qEJKespUIJeoUlsi5A32DftDABWWYBYqmI8yd2ZdoB2xntKziwp
         g+e/tfet2a7HO5CNyGpBOliLmQJB4aK9eWt1OUFhaKXeqRH7/EVw+rcU2cI/FQOq+sVZ
         +87TfiW3zaQhm4YBcJH73nOVxkc9xj7hFu9slxvHGLguhnc/JuYKUdIo8lbdccBLr+cB
         n8X3gQ3KlN+v40oqOCm4FsJBESq95JwcS0bg+rEwAcsTfRByCTQzEATJB5kKnit5Whvz
         /L3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=m0HkubMp;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ne1-20020a17090b374100b0020a605eff06si183417pjb.2.2022.10.06.06.26.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 06:26:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 037DB619AC;
	Thu,  6 Oct 2022 13:26:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 05ABCC433B5;
	Thu,  6 Oct 2022 13:26:13 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id d21f0881 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Thu, 6 Oct 2022 13:26:12 +0000 (UTC)
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	patches@lists.linux.dev
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	=?UTF-8?q?Christoph=20B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Hugh Dickins <hughd@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	Jan Kara <jack@suse.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	KP Singh <kpsingh@kernel.org>,
	Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Theodore Ts'o <tytso@mit.edu>,
	Thomas Gleixner <tglx@linutronix.de>,
	Thomas Graf <tgraf@suug.ch>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	Yury Norov <yury.norov@gmail.com>,
	dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	kernel-janitors@vger.kernel.org,
	linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux-media@vger.kernel.org,
	linux-mm@kvack.org,
	linux-mmc@vger.kernel.org,
	linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org,
	linux-rdma@vger.kernel.org,
	linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org,
	netdev@vger.kernel.org
Subject: [PATCH v2 5/5] prandom: remove unused functions
Date: Thu,  6 Oct 2022 07:25:10 -0600
Message-Id: <20221006132510.23374-6-Jason@zx2c4.com>
In-Reply-To: <20221006132510.23374-1-Jason@zx2c4.com>
References: <20221006132510.23374-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=m0HkubMp;       spf=pass
 (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Content-Type: text/plain; charset="UTF-8"
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

With no callers left of prandom_u32() and prandom_bytes(), remove these
deprecated wrappers.

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 include/linux/prandom.h | 12 ------------
 1 file changed, 12 deletions(-)

diff --git a/include/linux/prandom.h b/include/linux/prandom.h
index 78db003bc290..e0a0759dd09c 100644
--- a/include/linux/prandom.h
+++ b/include/linux/prandom.h
@@ -12,18 +12,6 @@
 #include <linux/percpu.h>
 #include <linux/random.h>
 
-/* Deprecated: use get_random_u32 instead. */
-static inline u32 prandom_u32(void)
-{
-	return get_random_u32();
-}
-
-/* Deprecated: use get_random_bytes instead. */
-static inline void prandom_bytes(void *buf, size_t nbytes)
-{
-	return get_random_bytes(buf, nbytes);
-}
-
 struct rnd_state {
 	__u32 s1, s2, s3, s4;
 };
-- 
2.37.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221006132510.23374-6-Jason%40zx2c4.com.
