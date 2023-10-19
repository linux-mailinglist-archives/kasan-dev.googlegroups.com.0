Return-Path: <kasan-dev+bncBCP3N3ERTYEBBM6JYOUQMGQE5XUBLNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B5EF17CF216
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 10:11:32 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-581d9b88404sf3392608eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 01:11:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697703091; cv=pass;
        d=google.com; s=arc-20160816;
        b=tYv+Fp2yf2Y+L1BlBpnYv6QdwnZT9rWxhCYHg0ofIMateXuXZN6km8cqpPbeW2Jmx4
         KkV0C1/TkjH0grnsyD8rCtQf2os4vbjBOlIyBOhKT9gL+oYBDOe8ZbWQ3iA1hdNmrT4Y
         qriX/zcVCs3Ss4J2HxAof5aAUUIo8tjNSw0THOfwIwDj1a2WIWjHQ5KEalc9vKAmDr2r
         kZWj9+BQr13aVbFPeEeveo5vx4rZ+jdvqOF3b5n2d5outzGmH0AxI60wFp/mbsAcVrNT
         GAFcJMWyP5E1FBS3GbmY6lF1xcRVYBfKik9P6hsa/sinwNqyz1Nka2TFl9ND6PYwHCkM
         Hj5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/9F27w/l76Qg4ZWSeCKGCAfQHjEYf9OYBb2tmpFyQpQ=;
        fh=seKKPDlUKrLjZ58shMu1D//fDSQP+hQGA41I0sYCYX0=;
        b=N82FaTCOeVjW0rMDp1ZdwkXlc/OdK58fV6RWtY00UEgzOn/zmPLT559ichwG2ZHB07
         jcBumfBoq6EhKtb0cyRgJislzEQzCeQ/de7MzftrLj0tjtxeHgODZ6rnoGe3m8gLCLKp
         tRsdYsx8EUuqVTESKZTb6qvQRkWNbqsbsK+Dd973jObs/ZAwov9QEHA644/uq1U/TOfy
         S3M/WFkUmXEo9R/jVPl38dtjsQxGw4ctZwFcl16AWs/ucBuydEimPVpmfVYMY+Jtzcrf
         zjaBfk2/ESI7BFEeAe7ObPhimdJ+lVf6MYub9w5TSaJigAzStGuTB0Wra/yfydfsjXw+
         Vdyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=On7fRHdP;
       spf=pass (google.com: domain of mripard@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=mripard@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697703091; x=1698307891; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/9F27w/l76Qg4ZWSeCKGCAfQHjEYf9OYBb2tmpFyQpQ=;
        b=IaPRB1zFhCXyENdh6AtD659SFmXzBTy5My8GUqqFl2lD50Btze5bUzS6bKv8Oopu1u
         fPpCa1McAMXDQeU+T2aUQ/hCodvZVshvHjxF5eVPIqJsxz9DluvsqZCk9v1jCdJI/msy
         efZlMLpmVEIEdtEMcJbuxjRmR1oCLf3guYKGPh35EqzPUM2p+cb5mhntupn7YIrJJKmv
         Tx5SDWbkaR4oYnBjZQdOIxSpVgZY/ZaBQNTGZaUl/OdbjAQFoSQ0Ul9jKIJo4I5P82jT
         CBSE+tz0RpYRHV2ZuY+hZz9GqP6rA2nAm53YdidmGSVloMWyRPWnN/3C4WiJiRwKUPw4
         Pwpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697703091; x=1698307891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/9F27w/l76Qg4ZWSeCKGCAfQHjEYf9OYBb2tmpFyQpQ=;
        b=YgfvUe8F+kdWLCNhL9HzaZNSrvZfG3YotztAx0YiQ3N0Yw3VhQekB3sjzBDhmrX8lw
         /5OAWm4ydHR/96X3enEOpWscSl8sRboZ/IeeEMpiIDUmsVxDfL3FZKxnLb+NcRTm4iGF
         UFORZVfxfXHhB/6l2Od/SAvPtaKyEmOAR335IRxP1da3GAAR8EVzuMqmDTsJBmCJtS0j
         iAA49UOG4WY26zVZQdhA75addwRGCVSCyirEJijauwtXz8ApOiBv1plljGS7E9G5lzPw
         j8K1qj1qiwGzfbVZkfdvJT/P6ItjHHhmFx5/t4642UvLtTKbm742DwCotOpt5NP1ZrBJ
         yHFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyLu445QPofDfaS8CD3HM2VZ8hcM9FGw8fPGKRLZhKWRVPiWab1
	xrd8YjPJBsoyBemLu/523/c=
X-Google-Smtp-Source: AGHT+IFZFCZU7BgjtuCGN32WeujQF76m06mZ3twf/+MmdHSKOb/VFnvqbGWBGtV5S9zHRLLvr360OQ==
X-Received: by 2002:a05:6820:1c02:b0:581:ed12:98c6 with SMTP id cl2-20020a0568201c0200b00581ed1298c6mr1533130oob.4.1697703091255;
        Thu, 19 Oct 2023 01:11:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5853:0:b0:581:d755:f05f with SMTP id f80-20020a4a5853000000b00581d755f05fls3999813oob.2.-pod-prod-05-us;
 Thu, 19 Oct 2023 01:11:29 -0700 (PDT)
X-Received: by 2002:a4a:a68c:0:b0:57d:e5e7:6d00 with SMTP id f12-20020a4aa68c000000b0057de5e76d00mr1478785oom.6.1697703089841;
        Thu, 19 Oct 2023 01:11:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697703089; cv=none;
        d=google.com; s=arc-20160816;
        b=IFGuRCIyqbnWowrlzZviGBHiwqAKHtND04AdM5yOLQ+UF0VVqDtkGOn0FAAlpSEUh3
         GGSXovKlObG8FfnMUZKKD9BTuoFW/E0lsJzqLe7N+RP9QbWrdt2bSQgADxqiUal2braw
         znItsWD/Wsq1cYqhDAk2zvdb5yH/AItqWylK+hlIu+MSvPdQSlaeUnwCrTiFB5/lj+e3
         wev3iZnYIxhRH55QxXvcoKfwIzn3lBtzy9ywMQfy+/txzB8/AtYoaGW97RrXGh+DC1hT
         sYLBt0ATzJaniF0Q1uOLj1FcuX6xXuo175q9yot6lE6zcLpqs1C7Uwzv3O0hPcJjP9pj
         OEYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=U6hHGcIgE7tww4kPN4S3oIKwaf2iLFvlKTaZBecZHlw=;
        fh=seKKPDlUKrLjZ58shMu1D//fDSQP+hQGA41I0sYCYX0=;
        b=hZhtd/y2ZP0UJfqmzAObRfv7S2C+7KwDxoWdz1/FvdQlME5lnQMvPDydUpcaSWrfgZ
         qp/KTQY+Cy3DlIdTq8KBYPxTdmO+B4RteCzb/vm+uxv7vBg3GiSFn8uG+AyFjniaXb/9
         MEypeViYbVy4Ax3XHjkiOaUq1LKsdMOHAzSX8/2Z0gz+pj7F1YxoVb8l+I+f6GJnNLSw
         oGzLql14uTHMWmxvanPcgI0aAGZXrAw8e9bGTU6ekUmf5Yo7+vusn5ojGSrZ1LzZeDvM
         vM3FWLAPvgz8baP9jOg+XhejFh/m/KnxOXStyzmX9pVhbDs8LLwd/Ntf8hEbmGpQ83rk
         R7rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=On7fRHdP;
       spf=pass (google.com: domain of mripard@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=mripard@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id e79-20020a4a5552000000b00581e037c0f6si467646oob.2.2023.10.19.01.11.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Oct 2023 01:11:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of mripard@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 77232B82491;
	Thu, 19 Oct 2023 08:11:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 52961C433C7;
	Thu, 19 Oct 2023 08:11:27 +0000 (UTC)
Date: Thu, 19 Oct 2023 10:11:24 +0200
From: Maxime Ripard <mripard@kernel.org>
To: Dan Carpenter <dan.carpenter@linaro.org>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>, 
	dri-devel@lists.freedesktop.org, open list <linux-kernel@vger.kernel.org>, 
	lkft-triage@lists.linaro.org, kasan-dev <kasan-dev@googlegroups.com>, 
	maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Thomas Zimmermann <tzimmermann@suse.de>, 
	David Airlie <airlied@gmail.com>, Daniel Vetter <daniel@ffwll.ch>, Arnd Bergmann <arnd@arndb.de>
Subject: Re: BUG: KASAN: slab-use-after-free in drm_connector_cleanup
Message-ID: <p5lvorprghpplw2gxxiajfea6xcjecevjkku7xg6phdg2l7jez@3cexjfyqqpg6>
References: <CA+G9fYvJA2HGqzR9LGgq63v0SKaUejHAE6f7+z9cwWN-ourJ_g@mail.gmail.com>
 <1ccaf470-4bc1-4a1f-81b0-2757a4a53bd7@kadam.mountain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1ccaf470-4bc1-4a1f-81b0-2757a4a53bd7@kadam.mountain>
X-Original-Sender: mripard@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=On7fRHdP;       spf=pass
 (google.com: domain of mripard@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=mripard@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Oct 16, 2023 at 04:13:53PM +0300, Dan Carpenter wrote:
> If I had to guess, I'd say it's an issue in the vc4_mock driver.  It's
> crashing somewhere in Subtest: drm_vc4_test_pv_muxing.

Thanks for the report. I'm currently at XDC but I'll have a look as soon as I get back.

Maxime

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/p5lvorprghpplw2gxxiajfea6xcjecevjkku7xg6phdg2l7jez%403cexjfyqqpg6.
