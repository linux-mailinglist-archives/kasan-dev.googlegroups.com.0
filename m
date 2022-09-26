Return-Path: <kasan-dev+bncBCF5XGNWYQBRBG7JYOMQMGQE7IXM3GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id EA0E45E9779
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 02:38:52 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id k3-20020a056e02156300b002f5623faa62sf4080874ilu.0
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Sep 2022 17:38:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664152731; cv=pass;
        d=google.com; s=arc-20160816;
        b=f54TMPtBdu/Gfh0t1N2xWvNOwLsr4x0M+sKBlqwrGpDd3J6IWlLGgGK8J/gsjovFcp
         Rpex8IFQSM0PIP1+CapI8AvcAlKjDScd1X2huXLy/erEmfX+fm1fGyPZreXKVwRiLM/B
         a230WkH0ql0sM6j0VlgY2qNN4WkY3gRINrzehfFg4R56HL2iQmJGzVKf+Y9RXf+Sjml1
         puF9DMyJw/I5L8svBb4Np9mrw/IYmRo/V0utMSlXsoItrjmvcICm7I9KYiuz40eT3Wnt
         tNs8BFO5egXGw0M21QMM0Dzr5vJsXN/aUxCgVIZXqvuxzOny4UW8vbBb/QHN5ICY1nK8
         xUvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jY/0um8RLVDCNxO/wGgGdlQTwy6x2ZAvIEt7IDmhMks=;
        b=NwsVp9gFhdQ3G5DTmf4AJyFTBJdH5ePAxqSBRASyq2U+fpFKFh+3sJ9aAgCaRO0OSL
         7o41JaPFNL2drkSGdyyb4zGIFVuHxtzgTWZJtpXWYAem4xtIH1QdZwDHwyTTGVB6QHLF
         Ek9ge8dOK+58iZF8uU9PG0CXRo3CoYO9lUQ4fgp3uJHgMP+r8ipEEYF8jXORRCzykFwc
         N/FED4R4fmqLdz3NO5aH4UGafUfoFc3lP+ySRhj1tiaXiGA7kYhKt0mo+02HuOqMWZNn
         HS14ss0h+Igd8/VEGTV3bqBDiMA2HofGHSXeBtJY4FiVMmvCgDeynO9ar8yLTyBJZZYw
         u18Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EloZHChU;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=jY/0um8RLVDCNxO/wGgGdlQTwy6x2ZAvIEt7IDmhMks=;
        b=BKMwxbJUoscV61rP0c5f0JrnIvO+c4OOKesWoGLBHNwFiZQ5ipfD0C0jnrDmUDqHiJ
         OGM/BRhkUq+ww0s24+sjSR7UAh/0efVfGfhDX9jexPEfCO9g4lDDiYlN2zyy5ud3m8Xk
         S0bZaNOnC6FMHtb9rRNFkYqH14jfchfVTJHRVA/XsEMqtppVaZbOu4G035+JELZclmVX
         kxVY0yTUEbfW4uvkw53BEV7NocRo4DsjFnjDFP5at3pPba04Rcg6cLx7jtk6Q0v2FvnT
         INUGz9en50UicBgQynVuiXMRztbWn7G5zBnxXawJZFbqMIGkq/FBVuhg63UQb48qafU1
         H/dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=jY/0um8RLVDCNxO/wGgGdlQTwy6x2ZAvIEt7IDmhMks=;
        b=mWWxlVjK4i6rT8XQOrNIjUrcuO6aSz9rYJYFIbk4aUSybGmu+O8uL5pPzyMudEHQuX
         iOTtpPw2diPJ67cIqKGn4UwVAB1NPItgXZYoQlGANxJ+LvBr7vkfd0aLuK54BU5upSVW
         V2zQqLmADGCPb3Gzc9RYsM4XgTQHoN3CkHE3wZHpydFAv24Pe2rX0oQ8NVPVBz3bFtju
         brLpnrRALCPDEUcAlb8fkkvax5Yk8G6OJ5Rc3Vu3aclw4QNh5ii2/09cosVP49zssCfj
         DtQexlghm2NhjRo+/NI2x7QrRNhhl77eNHHjCSPDb3qXDdfai0dsOgPgR4tQrQdyieeo
         Plkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3QlOaiyTj/EYySU6ffAQF4NECMZM4m4AK2I4hnLWQiBjkO2SFD
	8HTCCivbo9mTrNPCEQ4HwPg=
X-Google-Smtp-Source: AMsMyM45aDwEbfit8alO3EAM2uElojS9VPWywgWHUe/FY1K/rlxfUIMVGty3iRgoYzJokxNfED4HyA==
X-Received: by 2002:a05:6e02:2161:b0:2f7:becb:264c with SMTP id s1-20020a056e02216100b002f7becb264cmr5880066ilv.282.1664152731499;
        Sun, 25 Sep 2022 17:38:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1201:b0:2eb:1346:cc45 with SMTP id
 a1-20020a056e02120100b002eb1346cc45ls4139421ilq.11.-pod-prod-gmail; Sun, 25
 Sep 2022 17:38:51 -0700 (PDT)
X-Received: by 2002:a05:6e02:1bcc:b0:2f7:2d36:36b1 with SMTP id x12-20020a056e021bcc00b002f72d3636b1mr6774951ilv.240.1664152731087;
        Sun, 25 Sep 2022 17:38:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664152731; cv=none;
        d=google.com; s=arc-20160816;
        b=IDsrFGp907eB+rxAQMhfdp1G5ocuJJr2s52DKMGcSXn/sas1C2tDnodkfaEeZqw3wv
         JQBcHyYHDU5Wp2J6C783zQSat6z1krR8GMRtHurTNjJKBjEIqADafShU1e1F3ESfxiV2
         DYhSvnJf0LxPzkvzs2+ZnIFEZHoZ0E1p1EdrdSAkFSfTdqNZOAKUY0kHOpLi/m7rrmx6
         gzocnOjLOxHfseaAm6g9NkW6h/O2E4XzFMHX6AKXQYEQyVe8Ret3x8voaKIym9pSDqrV
         ykq7Y3P507ciLTpdYt2z5R/fouhiWn05KzihIOewWW5IsgpfGfEEonkZSClouqtQUNU5
         CO3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZsMZDiPJ05dqPEjOyzQRRCQyAniieUtquk7D7/uc9oo=;
        b=fRFfo1E4clhVr89Hv07EJs3jGYaoxeXguaCzxJVPz2Y3Schgipwf5amwgYXnrerSLR
         e0Y43YUdJD/4Q17S6BCVihyPi+YD8oFMzTkJmmVPd49Q1WQIdLry01YyHpmdYwePT7AN
         jPhtEoKk65HGFwxndlhr5lk8yj3dqFUdjqySLJkMTArZAd574jAQ6nJ1RumJWsi01/GG
         g2SuyPJJYKpaYi/YhLGAdnpqKrbH7sx5DDur6ZNQnHJXPTymnQe6yurLwaV37czEqxd1
         VIBOAX1Yp6rKKDpJ/vt/6DWkOUheK57SSVvg+ZAeqkjd7h0bW9JtMfXRbuTfzooKJoxy
         5HOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EloZHChU;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id u3-20020a02c943000000b0034a5a969388si669763jao.4.2022.09.25.17.38.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 25 Sep 2022 17:38:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id f193so5224712pgc.0
        for <kasan-dev@googlegroups.com>; Sun, 25 Sep 2022 17:38:51 -0700 (PDT)
X-Received: by 2002:a63:4b1d:0:b0:439:e6a4:e902 with SMTP id y29-20020a634b1d000000b00439e6a4e902mr18048148pga.212.1664152730415;
        Sun, 25 Sep 2022 17:38:50 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id t11-20020a17090340cb00b00172951ddb12sm9640855pld.42.2022.09.25.17.38.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 25 Sep 2022 17:38:49 -0700 (PDT)
Date: Sun, 25 Sep 2022 17:38:48 -0700
From: Kees Cook <keescook@chromium.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	"Ruhl, Michael J" <michael.j.ruhl@intel.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Alex Elder <elder@kernel.org>, Josef Bacik <josef@toxicpanda.com>,
	David Sterba <dsterba@suse.com>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	Christian =?iso-8859-1?Q?K=F6nig?= <christian.koenig@amd.com>,
	Jesse Brandeburg <jesse.brandeburg@intel.com>,
	Daniel Micay <danielmicay@gmail.com>, Yonghong Song <yhs@fb.com>,
	Marco Elver <elver@google.com>, Miguel Ojeda <ojeda@kernel.org>,
	linux-kernel@vger.kernel.org, netdev@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-media@vger.kernel.org,
	dri-devel@lists.freedesktop.org, linaro-mm-sig@lists.linaro.org,
	linux-fsdevel@vger.kernel.org, intel-wired-lan@lists.osuosl.org,
	dev@openvswitch.org, x86@kernel.org, llvm@lists.linux.dev,
	linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 14/16] kasan: Remove ksize()-related tests
Message-ID: <202209251738.6A453BC008@keescook>
References: <20220923202822.2667581-1-keescook@chromium.org>
 <20220923202822.2667581-15-keescook@chromium.org>
 <CACT4Y+bg=j9VdteQwrJTNFF_t4EE5uDTMLj07+uMJ9-NcooXGQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bg=j9VdteQwrJTNFF_t4EE5uDTMLj07+uMJ9-NcooXGQ@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=EloZHChU;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52f
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Sat, Sep 24, 2022 at 10:15:18AM +0200, Dmitry Vyukov wrote:
> On Fri, 23 Sept 2022 at 22:28, Kees Cook <keescook@chromium.org> wrote:
> >
> > In preparation for no longer unpoisoning in ksize(), remove the behavioral
> > self-tests for ksize().
> >
> > [...]
> > -/* Check that ksize() makes the whole object accessible. */
> > -static void ksize_unpoisons_memory(struct kunit *test)
> > -{
> > -       char *ptr;
> > -       size_t size = 123, real_size;
> > -
> > -       ptr = kmalloc(size, GFP_KERNEL);
> > -       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > -       real_size = ksize(ptr);
> > -
> > -       OPTIMIZER_HIDE_VAR(ptr);
> > -
> > -       /* This access shouldn't trigger a KASAN report. */
>  > -       ptr[size] = 'x';
> 
> I would rather keep the tests and update to the new behavior. We had
> bugs in ksize, we need test coverage.
> I assume ptr[size] access must now produce an error even after ksize.

Good point on all these! I'll respin.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202209251738.6A453BC008%40keescook.
