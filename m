Return-Path: <kasan-dev+bncBDR7LJOD4ENBBJXGRKZAMGQECZ42NKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 16F0D8C4A86
	for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 02:41:12 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-43e1a913c49sf914651cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 17:41:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715647271; cv=pass;
        d=google.com; s=arc-20160816;
        b=JOQALjfg4no1lUBab050vw9ndFCgC0LDQ0mHLIy1CVrC3FRSMYzt6gKKt8fIfO7Bc5
         CjqIvE0R2D1SeLxPqaAW268nBD4T+1DYK56ZzzXCW7GWI5NYK0KfliSNTpKhfWcDPwUQ
         kYGr5Pg1XkNJidmppH8duD/6FVsdR1Act3XOmfLkhZHyAuqrVC/oiPK/ErvaizHUC6ah
         gDvnIRjMUWlTMn7XJ0hYY7HLn3U9vttPadloo4HXRu74s/S+1Xjmny5YT3XObMAi6q/h
         rjNBuI4YMLGoNN8XSt0eGltQnVbOS4BDnt+rXGx2OO8roBl9RnoDqYbZ2tXqY1nRj1TT
         GVAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2nt9QCY5jSKf+aZVNUq0lK83BYoWuUZMsmp0MAtNILw=;
        fh=k3ROpOJCCPUaRLXaJzfkOdBarAEg4Xfie+w9qskcuY0=;
        b=TjWkDtn2WL6XlFdvlRTbcAKjD3W3vLAkWYKPnaZpA00uHBHlGnyUNPkvLme37mPnEG
         I+/MpxgwAJWa/8ACVSsB7bRakm2+HtG3ljNJgRfBoueQcGYnjC5sFDbYBIKvxzJb2O2z
         +Zw6fMz5DdBoYdW35uwOdmD8Y6mF1bywo9hC2Z4ucrisbxCQ9dLABBgf6VyFG7AT3J5s
         iIlWvNU8OtKbuQHJDPcDppZs2+Gh5NIkBnjQK9YNBmPtu3GHmbNDzzbXdohg88YdZxtz
         B/92TCxN9aO/f3AG5XbR0NtdaA/8gMp0CE0MgBRNb6umQ2SNNHPCyLGKSDEOS5a657RJ
         exnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=bjuRmgBX;
       spf=pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715647271; x=1716252071; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2nt9QCY5jSKf+aZVNUq0lK83BYoWuUZMsmp0MAtNILw=;
        b=PoZXBp7hEnOEkq68X/aQ4Sn7fGHtXnIlxe3uynmb0P/M2ZLpqTUjxwQFr0Jru/6vdV
         Usop02eDF2nYb4bmkE1lcbkdghMvP9Dg9Uxn8dc09ftRcJm2TA0T6Sm3zWLd5Lhitutc
         6q1eLYVBpPqtA5ctLOfjun9/aSdKLm9wDfNGO1Vk6V9EzHFphZRxLQzZ0R+TChsKz7/c
         hI6VNPEDbB14mkKaZtbmYKxdgQ8ZeyE2OoqBtsxiYvGqoNpiK4dMV4qYuzmc2vrIcm5g
         W5tlfmwPQnW0624gLqFqWKsCKj96TDFxJpiqJXQytNi9m3GDURNbKSRssti4mAhDvtjh
         7MKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715647271; x=1716252071;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2nt9QCY5jSKf+aZVNUq0lK83BYoWuUZMsmp0MAtNILw=;
        b=ViyBeCas4QuYN38JkrufnuU/0257/QbAU7z8xvGpxXJ+5vd9yU9Z+7QTNS47cBdZ6Y
         gYP3O4Ns9uRDTuiADrVx0bvtP76JRW+JcT9bfVJxd3dYIMKKJLKKh7iW+QAgX0QG3LZq
         hCMIfQsFXiO6u8nT1LC51TbEARjNWKKKjs3vPAeYULynwsdudh99Z6bIwQIOcmdDvhEt
         swAwzNKEVtc1mTfAuOo0/lD/YVQbH2/fhSzaDK6ov/qYQ9SOPVM3BFJagP0Giznd6n0f
         5o85jFT12P5CFPNcynZSs4cXSGzcK/FJVZNacKaK4YhiBcLicDGoqDeqT1twl/FHMzGx
         VJuw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKE0JZqrp+IA992khfEZpFvaKiqUe+pX1Uu1oW+YPtOaRkiOgUEMn74pGuchFyclLYeZMzPaIou5tvG9uAjq7gqduRtNDIHw==
X-Gm-Message-State: AOJu0YxnVwr7e8fs+R7faJH/h0rTTguDP5DKkzxvLino26Hrd0WX2cp3
	5wd9QjALicZf5CoVtHvgU17dZSmdRrMK2cDmW7JVzZfQTMTmHbyK
X-Google-Smtp-Source: AGHT+IGWXFTiKLiNMw5k1zFI9GtOj1yIP9S90tr5qf6G8ElR/wgZ4NukAXEgArnzeu2GNZipxWo/Ww==
X-Received: by 2002:a05:622a:1928:b0:43e:1124:3c4c with SMTP id d75a77b69052e-43e11243d95mr4971491cf.28.1715647270861;
        Mon, 13 May 2024 17:41:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ab0e:0:b0:de5:a3ef:27b9 with SMTP id 3f1490d57ef6-debcfefd0d6ls79485276.0.-pod-prod-01-us;
 Mon, 13 May 2024 17:41:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlmj/1Aj3x8h6YxXAxwUg4D2N7NN+b4H7a89it/74x0G5r7AciB2dUAAM9pxOUwt18/A8/JibvYuD6IWlKstpRkg4oO2VRlfUARA==
X-Received: by 2002:a81:4885:0:b0:618:25fc:e2a9 with SMTP id 00721157ae682-622afff68fdmr110505687b3.38.1715647270038;
        Mon, 13 May 2024 17:41:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715647270; cv=none;
        d=google.com; s=arc-20160816;
        b=JV38GKBVfs3cR9tDZuJ0M7Tk7/AyGMePp3SjdMwnqTFCCt205h5VYL27Gr2OPpp89V
         2s/0DoMy+Fn5w4roiiwjcF/hDGtrmPpNMXMzQOzEc3v/mA4qtEILUvVlHuO7mO3ubU5Z
         js89h9aSaYRVIo88Ay4KdxHpP5W+VyeflBdQnCgrMkTWzPbx8ee+KtewO1eL8Ifeock9
         NYxVHPoFn/HoqajSJ7wNfq5FltwxVljWFqQjP0BbTLd5ZrxYyYcahRmdfA4HIEOrl0v+
         2cn9dWWWAAQIUzP2wHZOzbL5tvT9A90HM064PVkYWP181tbt8WOxe7wTMvINI2f4ZkgW
         3oxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4+jXX/hz5Sn9kr6jAJ2T/dJnnr4GmboRRKaDLKSwuY4=;
        fh=7kzwHfsgh3yH3I3Gyxi2rZ3UztsGMyDoA8hfCXSoemc=;
        b=RtGhvWlwRmAiaCMfwSAgKBj4xrggEsc6IxvKR3d1pY/+7CX2zgVvpyKVOAr4ZPtKij
         GwC4lL/FZ5Glyj4QFwZ7tOgfUBnjcFG3msgveRgV0lJVBusx5rV/tTo/Kzec986ONGXl
         4lT727ArIXmtfuEvvVmhZl/LdAaRd2EmqncoZkCN2Dtbl4xYShwG+/rEwwZravtmtqI8
         m1RKItWnsCiWAf5dPKuOtN+0EHiWzdGmTWV0GdSFNZJQmVzJZDlHdpZtD9/+liwq59q3
         LmIcLac5Ba/3xs5twEBKdtDr6IQWzoADp1CHMdoT7lDtlW9q2UU/PRRjbgMtdcJHRzZM
         nliw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=bjuRmgBX;
       spf=pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-622d1a98ba9si3533547b3.3.2024.05.13.17.41.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 May 2024 17:41:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-6f4521ad6c0so4095011b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 13 May 2024 17:41:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVgDYhU6w7OKrrwXnzpLNQOEzHiqtLsT78yXUDDZwRRC3k+JwJ/AhrsuiX/OwD6+kFr6qsDoSMyGhI/tbe3cfqS+R5LuGlR1Rd7yg==
X-Received: by 2002:a05:6a00:1816:b0:6ed:9493:bc6d with SMTP id d2e1a72fcca58-6f4e02ad1dbmr11266559b3a.12.1715647268814;
        Mon, 13 May 2024 17:41:08 -0700 (PDT)
Received: from google.com ([2401:fa00:8f:203:3d25:e0fe:b3d2:e626])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-6f4d2a665ccsm7965977b3a.23.2024.05.13.17.41.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 May 2024 17:41:08 -0700 (PDT)
Date: Tue, 14 May 2024 09:41:03 +0900
From: Sergey Senozhatsky <senozhatsky@chromium.org>
To: Jeff Johnson <quic_jjohnson@quicinc.com>
Cc: Miaohe Lin <linmiaohe@huawei.com>,
	Naoya Horiguchi <nao.horiguchi@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Minchan Kim <minchan@kernel.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 4/4] mm/zsmalloc: add MODULE_DESCRIPTION()
Message-ID: <20240514004103.GE950946@google.com>
References: <20240513-mm-md-v1-0-8c20e7d26842@quicinc.com>
 <20240513-mm-md-v1-4-8c20e7d26842@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240513-mm-md-v1-4-8c20e7d26842@quicinc.com>
X-Original-Sender: senozhatsky@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=bjuRmgBX;       spf=pass
 (google.com: domain of senozhatsky@chromium.org designates
 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On (24/05/13 12:37), Jeff Johnson wrote:
> Fix the 'make W=1' warning:
> 
> WARNING: modpost: missing MODULE_DESCRIPTION() in mm/zsmalloc.o
> 
> Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>

Reviewed-by: Sergey Senozhatsky <senozhatsky@chromium.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240514004103.GE950946%40google.com.
