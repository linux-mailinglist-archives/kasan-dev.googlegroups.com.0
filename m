Return-Path: <kasan-dev+bncBDRZHGH43YJRB4GM4LBQMGQEAMHSWLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id CB20AB086A3
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 09:29:53 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6fb1f84a448sf7228266d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 00:29:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752737392; cv=pass;
        d=google.com; s=arc-20240605;
        b=Tyr1isxoo/IgeY8zD/ebRJGwqL0fW9+mj/V3ZBbhyYhNK9TiwRNTlTnD8XektpIT7t
         lwboX2UyOCUEaZbqupGQWxwEBmgYEepnLmRsIh6rZaTDYwGyZqaHa1S+UeIkF/AuN8qb
         2iCoboxioKOh3WtMGN6xN8WWLix0WFkNAQ7na9uEAA8vwWxnD715lAkU08Bcq23MJ0Hz
         tu/zoFEB7dNfe9itqRvaE5Rc4L+FNfloRe5bqyM5JRTCqf+4OQzsH6RGN4gOsNpmbQcM
         WqMmEm5ehuECJooA/FNMt0CAQEuWWRBMijPvlIK/Ai8RVmK29rlsqBBLON8m9sRLoos5
         a/Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=2J0t9muV3lib9jm1cwGZyZ3QdQfN/LrpZ91lVUPbdrk=;
        fh=syO0H5ASPqahyZNWXO7owoOis39inI97LpfUU57i7ew=;
        b=ZtuXLd2zhEHlprsS7SQEFQp65qAwuAXd6pl8PBtBzlvxVTBoOxQD6zYCUBvlsNma6J
         wQ0VswgrpD5VcqzhVeA/+J0PPOsR93jH/v4Sv50gJRSWcEr0aak2qeLdbRuCiXfzdKSD
         NxDfS8S9H+KiiNh+FbzvDwuRjDBOyh9aWg8BuOxiKzRTAvt4hquiAzAkBg3Xxo8pZfjv
         33Kn51k8d2oL6ezMtvoGvHPyuMW+f+rWOKZL+FXxL2Xi+swa12/6rO0/qWNucNWHRr7J
         hN6riw7vlzGRmS5rPfhQVcIFrYoxc1vrZEn80RMwOMFcz7GqceteF50MotxquJ44wy3n
         AKzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=e77FtNRC;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752737392; x=1753342192; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2J0t9muV3lib9jm1cwGZyZ3QdQfN/LrpZ91lVUPbdrk=;
        b=mHC4rFIDDyXmBufTUJk0CgPhfQwo1I0/2/KQPmMT2bIQRUDdyfgsl0JfWP2oYXJ4Qc
         Sk4vGs6Xa9nUtHhik/jNkA4xRIarkmg385vSV6xnUuGMSGHpa/hQ13aGTIFQ4aByzY17
         1l2CHe7UNu8M68BwRAMFgRsIu+RhMRj9VZE1THRoAeQPVTTKW/pFcX9oVecUKUJfaVyW
         g4MTPRsl/iCNc37rquV/Yt6gH6V1d3wsbbAGcBXj29ekCQGtwF5WTGNDGnaBQujbrXH6
         30oJhYhUcyChwgI0bULzBrfpiki/SNr8HxDpUaSTYd7No8t2AHUmpqvLQn665EtH73ji
         J5LQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752737392; x=1753342192; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2J0t9muV3lib9jm1cwGZyZ3QdQfN/LrpZ91lVUPbdrk=;
        b=IZ7RydTyNyKDU7a87oeYRRh/lYQlyj8/qvirVi/cp0EZSOxNuZDypOT+U3ZXSD4av7
         F8oVZTFUf2A+bnrArtm8zSgxOxtXlnI9NA/2lZq4hb8hdWa11YrVNhH/npvakDyYcBR3
         ISckYI8dFZHnOGaJxTU3pvLPVYC+cBhp/G3uu/9V9FjuOjwOi+fVty5BZCFXwZXfmqzh
         wH6eT9x8nJL35z+ni2ZuvHEw+NxvQUKfOO90T7NDupBOm0up8jT4ms08gI2paWYzqztA
         zBQMXnX0wP6aifJb/WRfxi4ocXhoao4ei9ErJc0eH+TSlZWhyVNNSl3bhg7YiwN11a34
         aGbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752737392; x=1753342192;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2J0t9muV3lib9jm1cwGZyZ3QdQfN/LrpZ91lVUPbdrk=;
        b=A5nws4RrFDyImsemyfvbig8gcLkbQ441ZOcSXP9kZC2ngcSNhYZPCHPlhUpySHm2gr
         l7bwPJKNpFtS2xsNgYbjUFqPIc/pGANMlxm9o5KInsy/Bl/I59s3/D4l21a9EUTnqyE3
         wKGi83hGAu7gPV40XwzKOnZCMlz9zUA+8Nnk6OnQeACJogFdgb6VQapaRHs8498hcIJV
         bTIjUKGkq+V8M0S7VPjFJHmEzCKlNuCp1DummD/tyxqYKLm3zvtWgXMymvCwSLbMlYGJ
         vOvBHJg0MllAcQOHxbHY+y2uhYhny03nvKt8kGJdxXI3W7MjuxdNPhv05rK+DXqemtfs
         LY4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX+hCBOdVq+cdlaYWHFI0OjaRhSLIn7umZK2xraGDUx1H+XSj2IX+V5vL+BqtcSaUEppiVPUg==@lfdr.de
X-Gm-Message-State: AOJu0YzIFFARJE5uw77B4ivu5qxY2nZF50ha6zv2nz5sZ62EILboFHzs
	SXYnxTUVQG+QsQ0huUC7DVhIk3l3hX/xfuLBmpmv0L7anghdFA3h0/xX
X-Google-Smtp-Source: AGHT+IHrGk8NWCZ3ec+tNyyATVwZNPzCrMJBL6/t4cZFwZ4U8wQhzGWjY/c4LRTMe0TVuJWGh1qdEA==
X-Received: by 2002:a05:6214:3101:b0:6f8:a825:adea with SMTP id 6a1803df08f44-704f69f558amr82217586d6.15.1752737392400;
        Thu, 17 Jul 2025 00:29:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcrCde/J4qJzRDQ8FdhZg3ovI69A9TaQkSVMGX98R+dgg==
Received: by 2002:a05:6214:27cb:b0:6f8:afe1:86df with SMTP id
 6a1803df08f44-70504ac4aaels9643486d6.0.-pod-prod-08-us; Thu, 17 Jul 2025
 00:29:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXiGhAcFl/wOKAmS6kGt72y2HmUnMiXPLmALpKZvS3zQe/EzG9w/22qeFeajqGwMW7xtnXLLLrAsOo=@googlegroups.com
X-Received: by 2002:a05:6214:5bc6:b0:704:a6dc:525d with SMTP id 6a1803df08f44-704f6aa03d3mr79592856d6.25.1752737391421;
        Thu, 17 Jul 2025 00:29:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752737391; cv=none;
        d=google.com; s=arc-20240605;
        b=hjYovcuIfUa7GCIf3dyU0ax9RqkjnBIZ0sDtDLImKdfaAbZFKWKydji5pCV54mIYgt
         G4eHDAoWabNCaPy6lgpdNFsGfeWiFhiLmcgnSPRXUf5KsyglPtSr0h97c3RFB5/1vxah
         iPrDYSv+bvIRLCKwR0ApGb0YsG4RQvKocXGAhvzBR151hMFJOvQozEIVH8Yq2Wl6TwHB
         7AXZfM1YlM2T6+otWjWIWpwdnSpbxG8a+xqY8DQrRuFsU5iA38loBTp9hbb+2C6gpxEc
         d5NvW9IPDGIvS3VhrN98YsG3X8l8EUJw3/n9XtsbDBtlC9zDANGzSV3AF95fyJQwHn4U
         VwOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DDF4dAgrnw34VJPjjy2t0SDWi0MqtesXMSOxY10q/fY=;
        fh=KTVCcrw8vwYTqexNKcqah6DPCbDzPtXQ8bf83MOCsBA=;
        b=dvQxpmTG1a5pUyU52g8DhJtfpH5/V4i2AyGF2g5VqKGGahTE1t9YZoO4kh2wudTjk3
         flc+kmXu5kIOpSafNJm/sC5WS1AInM3k4+E1UnayEV9wY71Surtagy/t2c94qeG3VA0Q
         IQ5mQUy7Zt6VvuuamLO2ENDV1KEqIt+GLmvHwbTdX/ro7oc6hH2qiEsR9W7STi/LwTCE
         5rTyIJzuV37angV9lhqe0kKyTBcj6lm8GjdlNqeAJ/aJgQm5ZSbhwRyznVWbkPrufMVY
         Zdi1ZjB+dtrLdVQ56BZT3BcW1JgJ9ZSRc4wYv32koatJ7mfftXnyqsa2wVm0I9+MR6CI
         GwNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=e77FtNRC;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7049798f3afsi5722556d6.1.2025.07.17.00.29.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 00:29:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id 98e67ed59e1d1-312a806f002so116537a91.3
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 00:29:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU4UHyjTGIGA7UNQn5GtK4WlOAKECNOqXbltNq7uhD0BnbYPWZzGfb7iVbUixovFYfCUMXOimea598=@googlegroups.com
X-Gm-Gg: ASbGncsst+xFGRowLKAgFur84VyoIlFL1zDysKMy4qXXl1p/O6bMFanu+5tpQTcqV8c
	n9wws0kPXvV9DolX0jAvzBeZrxrSKrAa2OFJa/cd70PZru3l6JKdUdwa0++sGv7TFCZhIRsg0I0
	YqE3WPkv7MyGXCMS7nAp90v235LhTCNBW8/yHaMnmq1wE7+uvWKKrZds0GnDWwa1E3ukfjMNsAF
	QAvBbOD
X-Received: by 2002:a17:90b:1348:b0:313:f9fc:7214 with SMTP id
 98e67ed59e1d1-31c9e6ec8c7mr3596901a91.1.1752737390348; Thu, 17 Jul 2025
 00:29:50 -0700 (PDT)
MIME-Version: 1.0
References: <4c459085b9ae42bdbf99b6014952b965@BJMBX01.spreadtrum.com>
 <202507150830.56F8U908028199@SHSPAM01.spreadtrum.com> <c34f4f606eb04c38b64e8f3a658cd051@BJMBX01.spreadtrum.com>
 <CANiq72=v6jkOasLiem7RXe-WUSg9PkNqrZneeMOTi1pzwXuHYg@mail.gmail.com>
 <24e87f60203c443abe7549ce5c0e9e75@BJMBX01.spreadtrum.com> <aHftocnJcLg64c29@google.com>
 <7afa22cbbb85481cbb3fabb09a58bd63@BJMBX01.spreadtrum.com>
In-Reply-To: <7afa22cbbb85481cbb3fabb09a58bd63@BJMBX01.spreadtrum.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Thu, 17 Jul 2025 09:29:35 +0200
X-Gm-Features: Ac12FXybXl51xhyGUacxmi5kHiXFRNN_uQ8UNQosRGKU2Urpiu5evh4hcAyLZNM
Message-ID: <CANiq72n3L6JE-pfR=8x0GUU++=8nPLw44oNEV1shdsHqXbts8w@mail.gmail.com>
Subject: Re: Meet compiled kernel binaray abnormal issue while enabling
 generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on
To: =?UTF-8?B?5YiY5rW354eVIChIYWl5YW4gTGl1KQ==?= <haiyan.liu@unisoc.com>
Cc: Carlos Llamas <cmllamas@google.com>, Alice Ryhl <aliceryhl@google.com>, 
	Matthew Maurer <mmaurer@google.com>, Miguel Ojeda <ojeda@kernel.org>, 
	=?UTF-8?B?5ZGo5bmzIChQaW5nIFpob3UvOTAzMik=?= <Ping.Zhou1@unisoc.com>, 
	=?UTF-8?B?5Luj5a2Q5Li6IChaaXdlaSBEYWkp?= <Ziwei.Dai@unisoc.com>, 
	=?UTF-8?B?5p2o5Li95aicIChMaW5hIFlhbmcp?= <lina.yang@unisoc.com>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"rust-for-linux@vger.kernel.org" <rust-for-linux@vger.kernel.org>, 
	=?UTF-8?B?546L5Y+MIChTaHVhbmcgV2FuZyk=?= <shuang.wang@unisoc.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, =?UTF-8?B?QXJ2ZSBIasO4bm5ldsOlZw==?= <arve@android.com>, 
	Todd Kjos <tkjos@android.com>, Martijn Coenen <maco@android.com>, 
	Joel Fernandes <joelagnelf@nvidia.com>, Christian Brauner <christian@brauner.io>, 
	Suren Baghdasaryan <surenb@google.com>, Jamie Cunliffe <Jamie.Cunliffe@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=e77FtNRC;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Thu, Jul 17, 2025 at 3:35=E2=80=AFAM =E5=88=98=E6=B5=B7=E7=87=95 (Haiyan=
 Liu) <haiyan.liu@unisoc.com> wrote:
>
> The config file is included in the compressed file kernel_artifacts.tgz w=
hich can get from ' http://artifactory.unisoc.com/ui/native/VERIFY_ANDROID/=
1746740/PAC/sprdroid15_sys_dev_plus_sprdroid15_vnd_dev_plus_sprdlinux6.12_k=
ernel_dev/ums9632_1h10_64only_k612-userdebug-gms/sprdlinux6.12_kernel_dev/u=
ms9632_1h10_64only_k612-userdebug/' . The path is 'kernel_artifacts/ums9632=
_arm64_kernel6.12-userdebug/kernel'.
>
> Can you get it?

If you mean to report upstream, then please post the config as a
simple text attachment here and clarify how to reproduce the issue
with an upstream kernel, as I and others have mentioned since the
first reply.

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANiq72n3L6JE-pfR%3D8x0GUU%2B%2B%3D8nPLw44oNEV1shdsHqXbts8w%40mail.gmail.com=
.
