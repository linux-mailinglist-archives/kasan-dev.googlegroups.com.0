Return-Path: <kasan-dev+bncBDTN7QVI5AKBBF64TXWQKGQE35VKMHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C15FD99EC
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 21:23:05 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id b10sf467627pls.8
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 12:23:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571253784; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZK0AgVhtU1v1INHHiBSAg5L8mFqAFQNTLc7xpniqCWN3OzsotOvtlVFMuiGjYDbZ1z
         fGy7LoSf3RT+cfRcta/z91EOpCduIPzFZY56AV6Rs/z402xq9cANipZX29qiJYluSk81
         uU3StzE4dm1yC2HOINRzAqIDPS2K0vYcLmuVu6WmaznhFh9N0qHCdqViDhAK4T6KlocG
         C1K3eUX3DQA9xgNywRxlWyIYeSE16b1UrKCl87f5HdYHJZB9doEpWDHJa6qKpem8TwU5
         Jsac/mpsfCsECUWp0KOO+PYzOAinphPulj+fLM/+oX+95HeYNnREzrX0Kfy0+AASQepJ
         GvvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=v0y/rqaSsDfuFHUBtuwQ8jAFnQC+q9D+IiX30/O47/E=;
        b=PkS1oeXR9WnIsy8LGadkA0bNHfyM/d/XfUhk9poot/XKicb9zFurYJXi4j81W3wuIw
         auen6/P2JEptZc9Kg8CDWj4aQnj9UZx6x/ve9WaY871gIioPzSqfaRKxElnlX6L78CW2
         Myfm6UhB1gr15/urewCptDjtwaKn9BXGOPyTY5rtR1ZRLJdYH1pEMAQnRJL4A8FSy9QN
         /JyH0tWVU2E5rORmfdFGlQnq0FzalEq3vXJLJrbnLC5cIPEInCJlN+byNS6iVeZpkySE
         Um/fgDqdvlIqya4Wrrz8p3NiZnToOwuZqqIG0dHdTA+T6pgsnmA9Lhd24yfpaoNOTolI
         kvRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 209.85.210.196 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v0y/rqaSsDfuFHUBtuwQ8jAFnQC+q9D+IiX30/O47/E=;
        b=d3YqpNwY8gGIHHn6U69PIqjnbpn6rEJ0bh2zZLtVL+0xOShApJatHW63t7M6FV1Tns
         b0oNex1E9BoOuQZeRuTB9lD01/vhPuJp5vXSJYp3JEvMmv0o5r/tD0i+n6f8lr9lHZlR
         dYiQ9e3mKijCVGxYZVY1ECZTCjr35vBwV49TF3NNaihxs99BaRvB/qH8Aw/K2l7hg63L
         BUH6+4xyIGATB82eFXm5dGmmF6Y+AdNcafjjP6SGX7AfU0zSwZkrIYLO+CDlsKmPS1Sd
         ik/b02ogj53zM1DM8UvLFZxjKXjrw5RvVbweafwfhzA1gqddZtIlz37kVZim9EKM8yfz
         Xc1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v0y/rqaSsDfuFHUBtuwQ8jAFnQC+q9D+IiX30/O47/E=;
        b=kaQFUvEH+ZArCBwIEj96ZifMBYiiM3POtUStvHuJ8B0z8cCgaDK7FjdZ4bxvxCvdgi
         Ber/XOczMMD5jem3D1gVcoZRfsmtX4vYl3UGJz5rzcU1383wEJBVbcaV9MNepEbJ2X0f
         mNmRFREzKpCcLT80KoFg857oT9bWHEC2lWhlOT0Bsz4BNZQ0xPGqWcjuX/QejJGrTN0+
         wGzEAVsHGlYDiuRgOqg5t+/tdvUWbHoJuRKBAAogbhaANaSirufkGVT1f1ra0oHg8BLf
         sGRsekUGz79ucrTGELVnC4Qz2XSQeuUrsSZ+nEJxh0xCzGo75zhSfvh0588j65tpvcWq
         MLkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWdBZelzbb/9iyM8xj2D0ZPHTa0y85N5eb4AZblCmFW40zzeMKM
	bd6ObFV/4y8nK7/QmZWnL9U=
X-Google-Smtp-Source: APXvYqw6BwwU7I3VS2Om5347IVMAVvYMFSEj+3sPfNN69rN8ejn14P3lL078IjOp979NyP8e7DIS/g==
X-Received: by 2002:a65:400b:: with SMTP id f11mr46838675pgp.57.1571253783885;
        Wed, 16 Oct 2019 12:23:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ff13:: with SMTP id f19ls5858900plj.4.gmail; Wed, 16
 Oct 2019 12:23:03 -0700 (PDT)
X-Received: by 2002:a17:90a:bd0b:: with SMTP id y11mr7247882pjr.28.1571253783497;
        Wed, 16 Oct 2019 12:23:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571253783; cv=none;
        d=google.com; s=arc-20160816;
        b=jAsolZBpT+ke1kHCsyyPoLaE19srKpKzU13SBAX+FsEpUgZEAWEEUlll12VaFs/Bgh
         +0kX3UhPzh3gPyHyXUNQ0ALyJtuaUuR/XK842N25ag8/v2Jz6/7tlBWTWHeBt/jawxPN
         Wr3fNphMSc6hyqK/SzrDpP+bE4iKN14U1t+KBri3UMW8szpAa5T05cMCgGU1A0eY7Q7D
         bPxTKCuBOtESr9/7sbj10fFsR0sra/mw9gZSDb9JbQpXVDbZ+L5FabTsvO45420Qg9gx
         hI3Ufe35FOEICu4Cc8k5xE7eigETuYF/WdcptFtVTqy8Ts8+4wp6pPHfxBHW386GpNBO
         oQOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date;
        bh=yNrX5NxWK+qA1o6LaqqAm41/yReowE+lc1hULeA+iQo=;
        b=vPy3XGgADJApoG2vIKLZToL5yZIWkC4/s0wVveuFDmbCLhNfxgfERYKm07Nz3KP5R9
         cHniVE2ceJ53S7EQnG+rIIy33ZVnG6CmFcrHCzc2102w+fbZSemkxryRfWeGiIoPoLx+
         UQ3S3o5NHJX/AbDKGjUlLFVD7/z+wmY67UfdfguDyPqyTW07B+8w/CdWNj6QrcHzJtUz
         ZZDyM9l7USbRrq190YdpfdUrl2WXueVJW7ZV8EAOZFUW0u8BUlB/AEimgh7qko02+ktK
         lwTmg1TbBYkT3J5ULJyj03oMbuxG01Lvd7C1pbHaQ/UOpSh7vg+TftjTqvSJN82/LBFT
         nA2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 209.85.210.196 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-f196.google.com (mail-pf1-f196.google.com. [209.85.210.196])
        by gmr-mx.google.com with ESMTPS id z22si448590pju.2.2019.10.16.12.23.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 12:23:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 209.85.210.196 as permitted sender) client-ip=209.85.210.196;
Received: by mail-pf1-f196.google.com with SMTP id q5so15304557pfg.13
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 12:23:03 -0700 (PDT)
X-Received: by 2002:a65:500c:: with SMTP id f12mr16812322pgo.233.1571253782761;
        Wed, 16 Oct 2019 12:23:02 -0700 (PDT)
Received: from localhost ([12.206.222.5])
        by smtp.gmail.com with ESMTPSA id k6sm26188868pfg.162.2019.10.16.12.23.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2019 12:23:02 -0700 (PDT)
Date: Wed, 16 Oct 2019 12:23:02 -0700 (PDT)
Subject: Re: [PATCH v3 1/3] kasan: Archs don't check memmove if not support it.
In-Reply-To: <c9fa9eb25a5c0b1f733494dfd439f056c6e938fd.1570514544.git.nickhu@andestech.com>
CC: alankao@andestech.com, Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu, aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com, corbet@lwn.net,
  alexios.zavras@intel.com, allison@lohutok.net, Anup Patel <Anup.Patel@wdc.com>, tglx@linutronix.de,
  Greg KH <gregkh@linuxfoundation.org>, Atish Patra <Atish.Patra@wdc.com>, kstewart@linuxfoundation.org,
  linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com, linux-mm@kvack.org, nickhu@andestech.com
From: Palmer Dabbelt <palmer@sifive.com>
To: nickhu@andestech.com
Message-ID: <mhng-5f3ce9b5-2b64-48d7-a661-7bedf58c50a5@palmer-si-x1e>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of palmer@dabbelt.com designates 209.85.210.196 as
 permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Mon, 07 Oct 2019 23:11:51 PDT (-0700), nickhu@andestech.com wrote:
> Skip the memmove checking for those archs who don't support it.
>
> Signed-off-by: Nick Hu <nickhu@andestech.com>
> ---
>  mm/kasan/common.c | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6814d6d6a023..897f9520bab3 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -107,6 +107,7 @@ void *memset(void *addr, int c, size_t len)
>  	return __memset(addr, c, len);
>  }
>
> +#ifdef __HAVE_ARCH_MEMMOVE
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> @@ -115,6 +116,7 @@ void *memmove(void *dest, const void *src, size_t len)
>
>  	return __memmove(dest, src, len);
>  }
> +#endif
>
>  #undef memcpy
>  void *memcpy(void *dest, const void *src, size_t len)

I think this is backwards: we shouldn't be defining an arch-specific memmove 
symbol when KASAN is enabled.  If we do it this way then we're defeating the 
memmove checks, which doesn't seem like the right way to go.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-5f3ce9b5-2b64-48d7-a661-7bedf58c50a5%40palmer-si-x1e.
