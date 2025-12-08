Return-Path: <kasan-dev+bncBDA5JVXUX4ERBRWW3DEQMGQESEX42BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 29A78CABBBE
	for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 02:35:09 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-64095177aedsf5520557a12.2
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Dec 2025 17:35:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765157703; cv=pass;
        d=google.com; s=arc-20240605;
        b=DPcHV/p2cx+wj/qVYAOMhshm65gln1XNhfpirJURjigAk5aoUUMh10Y3FtNlHk4B1Z
         HZaNC2XF2MU4nTz7//fisu6oLxUm/AvOImLT6edKe+0EVJ6TPRgYAYU9wl9J6VhlQ2wa
         +UgG99QCkgHlMvy4Mo18NJAp6Mlj99afffIQyk+HF8hbOq3lw/uYPlhiVQjo417bkJhu
         yuKcT+wF18WW5OotL1RtAqaXw1Py+FcHvuRIzFMqj/FOLqEs7nHiOiJ/oNL+V00YQraB
         Pw5fIZkKWUStxMxq9rPRDgjHsofVUn1N5zzf1n4hgqYwhZzdqIEvy+jZESnhSV2/cMTe
         +rzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=mEj8bLDOVYr77r8dOd/B54PY2s8z4SXJR0JydchWEEc=;
        fh=rxpCIxQYKwdzcBrtZ4el1zh0EO8xwo2wphLMn0uhS3Q=;
        b=Ueb7draoOOyMVd7TY4kGbND71mFcTL4exYtUVBTrRUoMKeTu4hxLjWBWXiHKMEuD5/
         Q+ik4C1TWj2Tzv1rDSLz7WHx4Sp/CMyP9LxhLj2QsyYBwF5Yg4Vi0AQnyxX88qp8Xeyc
         uV94ZtmftIVaNGwhX/Lj1e1BmOPZf/z0QBe1Qs4TAnkHtHph7hEbj4ns4qdZatIECTGB
         bucOaduLMniE8rkvbqNRUfcHHgkuHoyCmfFiWg1zqnCvX0hMZRmhI1z7mIKrWrf+wFGh
         UpA7YGcv+E3JVDooROg3Wn+6eDmrixAW4xeoU+ZUNMIp2W7I6rd7Uq0qofk6oIjoONKf
         yTiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xVMVRQdi;
       spf=pass (google.com: domain of 3rcs2aqgkccmsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3RCs2aQgKCcMsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765157703; x=1765762503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:from:to:cc:subject:date:message-id:reply-to;
        bh=mEj8bLDOVYr77r8dOd/B54PY2s8z4SXJR0JydchWEEc=;
        b=CXNdBLqMAuOGnXYLEL4BHN9W/8Trajmx5ox/bl7mBvUhnxn0fGKoW64jKZgXB/XM3i
         OF5Lmz93L+/n8betj2LKfPJMeONfcEm7y93ikrLyG6s616Ka3fghD4gVwQwKX1NY7BYs
         YOn7eMQIWhihUGGNg+2TwMJry0iQHY4ngbTMq2GBrk69DiKklxVahCYjNEMAtMnPhTgg
         HgRcbh3pjbY8Po+glTzQ7mY+r6jP4fqDlpcktPuB/5GixoAfMmqiqTCBXl0lq76ztX1d
         BCA4B+5BEGhoGz99nj75Wm1HNv3NmRaZZ8WyeN9mLSyDylGv6bwu0lSvKYgI8Y1n5Pk9
         j/ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765157703; x=1765762503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:x-beenthere:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=mEj8bLDOVYr77r8dOd/B54PY2s8z4SXJR0JydchWEEc=;
        b=GKhzt9p7xQiHRAZDs2IIkhXL2gkjluf8+Gfp/fAbsX2pqDGl3b01IpDV1P+swosuI+
         RT+Tv+uUcM3GKI2i24rcC02pE8xmH20PtWIHPk3d4ebIHqK2Rwdi3PJ1CWWQhgInUNnO
         Kla2jPHtn6QGR4gKAoKa3MOZkcd00NcpbtZiHEGv45i5WjJ4CCYv/Jf9mbDxtnUkRo+J
         7L9d6e8hHlHDbdbtKJe7sDJip8Vg6K104LxiBA8GHfAg0kGwTRywD72mo/h8w2P+QVbN
         9uFRES4swXQUpmzrv2+j6yliQCktM0nANE+E898bMfpPkgb2kEoDuelKrj/1qkm6UL5m
         n7VQ==
X-Forwarded-Encrypted: i=2; AJvYcCVyUTYXU3d/X8hr9vyiH7nUR60ahrMHTWFBiZiNhxJn2XYhqPfvWnDG3KEwz7IG8MRZ8Y8BJA==@lfdr.de
X-Gm-Message-State: AOJu0Ywvptt+DAbzK+TNut63bGyqzqnwaBHa3L3d+EK66/52i1vytrVE
	Pcz4z6G6NDmw3cJixoAzodlulc53eVmQeQmrROV+fQWzDRN/6SPUgQrT
X-Google-Smtp-Source: AGHT+IFjYNkfKmiu8LYX3FSiuJYekVwUa3FxRcZRJQ97cG9vvnjaeoxp9UUzUE17Sn7cHL8KRbY0LQ==
X-Received: by 2002:a05:6402:90d:b0:63c:533f:4b25 with SMTP id 4fb4d7f45d1cf-6491a3d24demr5669877a12.15.1765157703172;
        Sun, 07 Dec 2025 17:35:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWY3Zenm2M2rpCN0Rd0fU/qolNoe0M7kIImK/ezfk0kPsQ=="
Received: by 2002:a05:6402:534d:20b0:641:6610:6028 with SMTP id
 4fb4d7f45d1cf-647ad59b941ls2950369a12.2.-pod-prod-03-eu; Sun, 07 Dec 2025
 17:35:00 -0800 (PST)
X-Received: by 2002:a05:6402:440a:b0:643:1659:7584 with SMTP id 4fb4d7f45d1cf-6491adef2demr5503733a12.33.1765157700621;
        Sun, 07 Dec 2025 17:35:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765157700; cv=none;
        d=google.com; s=arc-20240605;
        b=RqDtkLjiD/DlPn/NdZJ9NXGqOvvqqwRw/PHcBLWW5u00rxU4N59LbORqme5o08Gv2S
         gpI9sBVk6uUnd8WGkircK32NhbpDY6ZSg134APoG/wjO9EsE2643XHamN7USSChMTblA
         dws0MR7H11CGXO1FQz6Dty2DbuRqJ/8QsFZa8acfFcjJQeunlcPih5zAkuSUf5YMGvNs
         C5uspZ3JM/2KD3r6fvxYZLDcTuyy3LKpimRuONcFgwByFgAyWAbfPWYUiUBYF7+qcdJv
         WwREgHzF4KM7tjSjL+0+4RcIKuKNDU/17CSmATDXV/JT94Uboe8+VsrglGUQ/RhiGPa0
         tj7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:dkim-signature;
        bh=zqW+wRrT8yWx/U5ZpiWH7Q47Ioy8EHId69CrUg9mCQ0=;
        fh=61XVfOX0mCGReeZztWfTUJNvZ+DGfh5Hp0WwR2VbiWQ=;
        b=DhvxKisy9kLJ2DdXeDt/CIfM7SzXBuQftdvPwa28/9X/iqgsapWh5qpxLfATd+MW6R
         F16aKkfMaVe3yMEJo/jUmihNLc/xK40z3Jb3xZ4uki2VwypQt7baAv23/KV1fhxz99Y2
         Zz5Pim0CpeOi8pnvVcKEshIrYuccUahJocDNFrINv0Dj97SskZCy07OIgYa5FRZwLfh1
         J6h0mio4Yv0uqFRPuzKqC5q0rt7LE492eGrRx7R3AA/C81y6AfPAhzKgLwWUAuiBSGLz
         bpEKIpCBTte2loUTos7g57aGfAewjNXpao8kZp32q1DrOrndq2g7vRTMgp+rxQagDTWN
         Cj4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xVMVRQdi;
       spf=pass (google.com: domain of 3rcs2aqgkccmsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3RCs2aQgKCcMsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-647b2ed8b0csi229999a12.3.2025.12.07.17.35.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Dec 2025 17:35:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rcs2aqgkccmsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4779393221aso24015665e9.2
        for <kasan-dev@googlegroups.com>; Sun, 07 Dec 2025 17:35:00 -0800 (PST)
X-Received: from wmcn12.prod.google.com ([2002:a05:600c:c0cc:b0:479:35f9:3b87])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:5488:b0:456:1a69:94fa with SMTP id 5b1f17b1804b1-47a6e65d1damr41394775e9.13.1765157700116;
 Sun, 07 Dec 2025 17:35:00 -0800 (PST)
Date: Mon, 08 Dec 2025 01:34:57 +0000
Mime-Version: 1.0
X-B4-Tracking: v=1; b=H4sIAEErNmkC/x3MQQqAIBBA0avErBtQUYiuEi1immogxtCQQLp70
 vIt/q+QOQlnGLsKiYtkidpg+w7oWHRnlLUZnHHBOjPgTrGg6CnKqFE03wltCIY2Zu8DQSuvxJs 8/3Wa3/cDkESu2WUAAAA=
X-Change-Id: 20251208-gcov-inline-noinstr-1550cfee445c
X-Mailer: b4 0.14.2
Message-ID: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
Subject: [PATCH 0/2] Noinstr fixes for K[CA]SAN with GCOV
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	Ard Biesheuvel <ardb@kernel.org>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Brendan Jackman <jackmanb@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xVMVRQdi;       spf=pass
 (google.com: domain of 3rcs2aqgkccmsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3RCs2aQgKCcMsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Brendan Jackman <jackmanb@google.com>
Reply-To: Brendan Jackman <jackmanb@google.com>
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

Details:

 - =E2=9D=AF=E2=9D=AF  clang --version
   Debian clang version 19.1.7 (3+build5)
   Target: x86_64-pc-linux-gnu
   Thread model: posix
   InstalledDir: /usr/lib/llvm-19/bin

 - Kernel config:

   https://gist.githubusercontent.com/bjackman/bbfdf4ec2e1dfd0e18657174f053=
7e2c/raw/a88dcc6567d14c69445e7928a7d5dfc23ca9f619/gistfile0.txt

Note I also get this error:

vmlinux.o: warning: objtool: set_ftrace_ops_ro+0x3b: relocation to !ENDBR: =
machine_kexec_prepare+0x810

That one's a total mystery to me. I guess it's better to "fix" the SEV
one independently rather than waiting until I know how to fix them both.

Note I also mentioned other similar errors in [0]. Those errors don't
exist in Linus' master and I didn't note down where I saw them. Either
they have since been fixed, or I observed them in Google's internal
codebase where they were instroduced downstream.

This is a successor to [1] but I haven't called it a v2 because it's a
totally different solution. Thanks to Ard for the guidance and
corrections.

[0] https://lore.kernel.org/all/DERNCQGNRITE.139O331ACPKZ9@google.com/

[1] https://lore.kernel.org/all/20251117-b4-sev-gcov-objtool-v1-1-54f7790d5=
4df@google.com/

Signed-off-by: Brendan Jackman <jackmanb@google.com>
---
Brendan Jackman (2):
      kasan: mark !__SANITIZE_ADDRESS__ stubs __always_inline
      kcsan: mark !__SANITIZE_THREAD__ stub __always_inline

 include/linux/kasan-checks.h | 4 ++--
 include/linux/kcsan-checks.h | 2 +-
 2 files changed, 3 insertions(+), 3 deletions(-)
---
base-commit: 67a454e6b1c604555c04501c77b7fedc5d98a779
change-id: 20251208-gcov-inline-noinstr-1550cfee445c

Best regards,
--=20
Brendan Jackman <jackmanb@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251208-gcov-inline-noinstr-v1-0-623c48ca5714%40google.com.
