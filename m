Return-Path: <kasan-dev+bncBDOYHK636IDRBWELTLAAMGQEC53AP7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 33035A9558A
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 19:52:26 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-43ced8c2eb7sf31259835e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 10:52:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745257945; cv=pass;
        d=google.com; s=arc-20240605;
        b=lO6rHievLxKI0UORp0dzrzxzxWCD6rw7mYJFgW+yO9/55iio6POkg4HroqXmgt/72b
         XtmAgEEA9KwIj7mCiRSkNHVBEPi//G7eP8VtwMZkFgKPiN/5PP1TKAVz+/RVZ+DQLtVq
         GsQUz/REfzMP+DQx+w7HScBgVDdjZkKXlcpTYpKLlO7clSdwOcHI4cBLS7jfYvc3WPSe
         qCDSgJFFx/5ZYm8k54t0czFRecJJkrxFnZChN0K3Vbs1hFINVM2cTrtJytuWYxiGas49
         A9VtTnVoHEGT3KSeNxrb5O6ao6VnDYWIqwRCPQ62n42k2tHFo7G7nOqUmHQPb734tyyx
         rTpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=zUmMEnFWhyTKCK/BYttfJ3XclZVQfTYebq7d6VRUOX8=;
        fh=PnOKf20kn6giOJfj2AfnKeMn/C+TZK6E5n6Fo7/SPxI=;
        b=YNbYC8GvmNnUfO3EFTz8aR7wK/bcVYaL2e75ntMCWNi394X/8AwTAWSEEUNRCzZlx8
         QA98FgVNNoC9EeoblQ+61SrmIZTVLH/0fPuCjoSo4N2Aw/+KkuOQWgnmHvTX1vKwy0ba
         JoranQ/msc8fgIxbRl8ck8K66RJeuPIHr4e5hrDgBvB8PApt7F10IhFOs2gE33fnfBHf
         jfQZnQaXCTaDJY322v8zHvy8bP71KAa6W5JD3MnxDC3y41ajD65D2jCHcss3cXgqE5D4
         SuhmYpHTY2JZBOMvk8VTJWJakkREh20ov/m7OUP9Ye1Ia5LGmuXLAz9tpaviwXsyzQWM
         H1zA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kyrWK7WY;
       spf=pass (google.com: domain of mslannguyen2@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=mslannguyen2@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745257945; x=1745862745; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zUmMEnFWhyTKCK/BYttfJ3XclZVQfTYebq7d6VRUOX8=;
        b=EuxwFWun4ykbHCzo8ZFCddKvFzhxcQoaIPDLNYbajxXR18ObEwOO3m/3ykq/jqE4On
         fZFX/IoPii8HAN9Lf4wuyqb/bFmxeQXa7zKphGuGnBxIqIBjE9VRowF8u/zrW4PRbtk6
         Wpjuvzu6UzTJx3UmXrwlfvDWPEREwjAOSst8kBJ0rcyAl9D8zrki6jCg1R8G7J5pB2Le
         Xm4gKT8XGnpudUg8m1/VmOnLoU9oxk7Meni0T8HXHUWS/lgawbxoy/th9xx7H4Df/lYP
         Xt3vb8RPvKcRRKYF/UTgLpaEtBB7cgPeYnbbtnaT7i6yVpOVPxmQb/bhok9RMkSnqkC3
         JsYQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1745257945; x=1745862745; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=zUmMEnFWhyTKCK/BYttfJ3XclZVQfTYebq7d6VRUOX8=;
        b=GxhhtIRqrko125UfHdM2ZDj0fdAt8FHkDTrHxfy52HM+NsXpkhfljQH61Kqf+zMHbH
         tKHYdqPYVDUO1ACehCsrbalH9zV05ICBd7XQUDS3jPh1KUWBkR9J33y4qYdIExoMz8i5
         MzuCic4BhNR4ZhIvJVazNslB+1zpAYxmBaCSAtiyi4SuDEFD6nOaHDR3dRs2I0aV02tn
         SE9Sqv+o3ow3oiHECH9uC1mDoP2GQicE1uR321NvRyukYnBxunjYQYRO5EZgtKUUEOFP
         7nlQMJMjM8vd37vJoG19H2aJLGf0DXRD5tW/wOVI/PnB0gW1W0Pledm0mizLq6WaDGdT
         FG7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745257945; x=1745862745;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zUmMEnFWhyTKCK/BYttfJ3XclZVQfTYebq7d6VRUOX8=;
        b=dF5lkTHx2Mx/lkAvLeVAvvYR/roEJJYU14fPF2+3XlUGMCWGI2PptwrFEN1AYIDPEd
         jBlYsHvdTaY4uMRoejHC/PlnOgNhVLc5ROXxH2Tk7q7/3VpHSXgZRo4Z0oNHrEl6buAU
         4kFkZzMVgpwl2IO5kl2lE2sNiROthVS6eJ6+iaab1wp69B8svht9URi9vdmkvsU+CaDo
         JqRDjt1xr3UEcm7TcNbDJ5nnhx4cv0X7kfLVilTsn4gcNCt3BtzXfkJZX+xrt1N/QzYS
         yEKdL48gWgj4IkfTwRq5LjxzZZzCZSMNqSLrMEvvUvzIk5s/E3wIJVHXXnUgujDlv6Gr
         gV0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKCZxflJ3Yqupi6n6Pu/RZ0aVVe5R4DXQaRQOqB5pTK4Mh85dvPYOHiwZIDwk6gm/gWYIizA==@lfdr.de
X-Gm-Message-State: AOJu0YwBSHmRqs1MJg7vHWLuNRsKZT09FwVbatbldATKfDKb/DusKuKv
	hBvgbs72kDu43rGK1zY+xeYzInVlVyUnI0BqLTKbomyajM2XH2y+
X-Google-Smtp-Source: AGHT+IF0Hjehv+DnscDX1VJxDVDwlU7ZYlkohSQR9XnW4pXFxo7yYSCHi5lRVmeSwuUBQPi8k5/icQ==
X-Received: by 2002:a05:600c:1d06:b0:43d:98e7:38dc with SMTP id 5b1f17b1804b1-4406ab65fe7mr93053515e9.5.1745257945068;
        Mon, 21 Apr 2025 10:52:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALnEWOLsar8An8wXengG/kSYtp7qUQ/jBzKqMHkKw7WMQ==
Received: by 2002:a05:600c:6c8d:b0:43c:edda:8108 with SMTP id
 5b1f17b1804b1-440623e70bels13438535e9.1.-pod-prod-07-eu; Mon, 21 Apr 2025
 10:52:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZZ3z5sPo3mBwV1DciFftBaSUyg6r/ykTFa6k0ddCbkoHM8k0meRXC2t31iLk7f649CxQ0Aw7YOqI=@googlegroups.com
X-Received: by 2002:a05:600c:a143:b0:43d:878c:7c40 with SMTP id 5b1f17b1804b1-44076c9c6fbmr68593755e9.10.1745257942496;
        Mon, 21 Apr 2025 10:52:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745257942; cv=none;
        d=google.com; s=arc-20240605;
        b=Na6EVZ2uk+FU/oYDdmBpKysATybVkhKOta7qZj3xmBZhFh1gtMmhTkhrcO6JOKJnvq
         3nKY000S2Kl/gG8afW13rYlL0a9jWd8nOsgfla+ZxGgbH+IcQnW00dRTtnL2/63mmI1r
         yF8l+WZYhu6tFSpUPRCBKaaDkS9by+NtHFKnJrkxBg4+3dk55nHL4srR+nfHXTqcqmr2
         Tl04t6LzojtzqlJaO+SFZbCafXqjva13/djjUeycGCWG6S11Zcb2courfWglHmCoWTOq
         AA8SehxufmRbTsj46r2GH7RAjtb03gWDsS6s5ABIMsOHAngSAju54R0jn1gvlZuw/y/P
         9m8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=0dyaqqnAoO7ZhNgU7hCLliMTdHvd+vrUxKk3jh9cO8Q=;
        fh=ANTA3puq1QO0EV/Rv7mgziIzvZ0tsjTBbRcXdGrf2S4=;
        b=cHhmjPVlgLmWNA6Ikk9NCSpZwDUGTavnqqlzGAvaGJ4F70T9W1oJhoXPcFIPUtr1Tl
         rmj+s4o9eu1MdQUBF2I4s6gG7b/ZJL7vx7HeuWjUowg9dQOTWsB3PfTAjfVZYwGEOO2Z
         fbaowBB155+INYcJJBNy8DoA2cwuyECBUYgqJsLYswr7fjUcE7PbVr16kTEqFGeiI0dA
         vdtltgihZjiOXwiKHh/ukAPmlrUyYLspLpmbjGfF4xLJPq7t5CdLUEfi4DZ8s9HluvqG
         Ppz0gGp0oLbxF7V2G73F3OA2EkispDtHY8OikAph/yBqhAkNdveW3t5jc+E76Haa9KQT
         uF9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kyrWK7WY;
       spf=pass (google.com: domain of mslannguyen2@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=mslannguyen2@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-39efa423dd9si145889f8f.2.2025.04.21.10.52.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Apr 2025 10:52:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of mslannguyen2@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-54989702b36so408385e87.2
        for <kasan-dev@googlegroups.com>; Mon, 21 Apr 2025 10:52:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUz3N30KKnICh3VU00lvGA192vXC0N+JPZXDweLndEEvbnuCtSvAEqinPFQdYOUIchqWSvazrTH0a8=@googlegroups.com
X-Gm-Gg: ASbGnctxtbvdWGCtLuNrqDaO0Km+xBEH3kwh7w7bzrCmCK8j7JSchWzriXipobU+tC7
	W/iszv4kFBwSuarWIfzzpz4e0ozxjidf5wQiW63kMhZPM6sp0I3kpZRk9MPeDRB6tZw/o7AOD7k
	ELtD74ZrJHcbSt+UWNRIpUoys=
X-Received: by 2002:a05:651c:515:b0:310:82a2:75fd with SMTP id
 38308e7fff4ca-3109055ade9mr14530711fa.10.1745257940913; Mon, 21 Apr 2025
 10:52:20 -0700 (PDT)
MIME-Version: 1.0
From: "Ms. Lan Nguyen" <mslannguyen2@gmail.com>
Date: Mon, 21 Apr 2025 10:52:09 -0700
X-Gm-Features: ATxdqUGakl4yAraVnofudgRCmEVzmr5cg30YzCsbnPxYBFnvsNvY8vE4Iy_E0fM
Message-ID: <CALrrK0EUdMx8oABGLkBt1RNN5HnHVVVyqZpM4N=c=k3+VdnF6g@mail.gmail.com>
Subject: =?UTF-8?Q?Let=E2=80=99s_Connect_For_Business?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000009c1b6f06334d872e"
X-Original-Sender: mslannguyen2@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=kyrWK7WY;       spf=pass
 (google.com: domain of mslannguyen2@gmail.com designates 2a00:1450:4864:20::133
 as permitted sender) smtp.mailfrom=mslannguyen2@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--0000000000009c1b6f06334d872e
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi there,


I=E2=80=99m working with an investor looking into new markets=E2=80=94open =
to a quick chat?

Best Regards,
Lan Nguyen

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ALrrK0EUdMx8oABGLkBt1RNN5HnHVVVyqZpM4N%3Dc%3Dk3%2BVdnF6g%40mail.gmail.com.

--0000000000009c1b6f06334d872e
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hi there,<br><br><br>I=E2=80=99m working with an investor =
looking into new markets=E2=80=94open to a quick chat?<br><br>Best Regards,=
<br>Lan Nguyen</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CALrrK0EUdMx8oABGLkBt1RNN5HnHVVVyqZpM4N%3Dc%3Dk3%2BVdnF6g%40mail.=
gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com=
/d/msgid/kasan-dev/CALrrK0EUdMx8oABGLkBt1RNN5HnHVVVyqZpM4N%3Dc%3Dk3%2BVdnF6=
g%40mail.gmail.com</a>.<br />

--0000000000009c1b6f06334d872e--
