Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMNFY2SAMGQEUMRZ7JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 10F70736B66
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 13:51:15 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-3f5df65fa35sf21024155e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 04:51:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687261874; cv=pass;
        d=google.com; s=arc-20160816;
        b=TfwleOKc4pY+jB3/uFfkapfCAhoiSqz93ZQoEMlu54Yb2ZiibFjAI5g1Pu+zL9fOz5
         BNAbrR4rShVFpHdgIl2Zfn7icOUTPIudzhR4Y+H+xtd1llAOBNZfMuXg3ymfuqnkqZl1
         W3cJ23gKMXx0LgKmo2hTlh/irQPGT4Pw5Hq//p7Av2esutAVZsecmiovCCbEcYaFMig/
         AK+ydzYIN9+TiK9QPV4pzLxX4voEkrc6MGS+ZSJU0Xg3KKKHTiYyvajIuyvCuOtTbKhG
         CeVPQLk54lzhLwlUEyNjCbxe7W2D5UBFmkC9u6eRmXVWHqm5rsCvix+43hNpzXgMGwsn
         CGpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=peLFs0IT6c4GJ7aYv7gyo8yW5wUOZ4Ez/8J1jqvS85E=;
        b=tUmE1f2/8YZWQQJgdnd3wuNYt+zZxT+7fW837VUlqfjW0QfXXWffxXle6oWGGj/HyL
         +CtqAkALi+GXO8jLv1YRR7/YfADJUWrOHbkLS1H5wav+ACmpg9iMku8oXXOGVrPcDwSF
         RcHyRrbhl/2OsribmTRJzm8bXwKolHD2QWp7P/A3wmZde1thSApUA4EMOPmumPTRTIkI
         4uGSvJsRZLUvRrMJrp3ZGCtjVE2mjBJMRY7hqE1f95u/hB4TC08Y+EQ91qo/ySyjTXT1
         Op53D7FKkJwnPDp3x3dPs2MT9GvVvvJ5yOrtXk2vMoaJCmgdnGMGMvfic14w5cwV563Q
         /H+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=3YLv+I26;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687261874; x=1689853874;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=peLFs0IT6c4GJ7aYv7gyo8yW5wUOZ4Ez/8J1jqvS85E=;
        b=Yr4RK/jaMvVoEc21tNNMRIuBqKt7g3/kkaUeq20CSwVptxsjhuzHLpRmIAZtipZ4Yb
         X0O+9y6KkMQ+8IiWwUh3+ceVNYfsPdyzrtB7Zq2UynOrUpVwPT2iKv9U6v9BB3OJaDmU
         KUiJRrXfGPM87N+6J1fEWkcL4/utvcQiZcKEOC6Y6jF+xBF2Qfm2QNOtambB2bmu/tur
         M8t7tj+2iYw6Opj3eQ6Er8AinOJcYWFN+vVJDrHAXBMsUDHYXDeWy2KQyGaWtwCuvzHE
         GW60jqt/s+cK84GaOMuCXwrnnNkOEEKNedHCySZOoeF43LB7IPuDp2bwN7/nvq/ksNwh
         8HvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687261874; x=1689853874;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=peLFs0IT6c4GJ7aYv7gyo8yW5wUOZ4Ez/8J1jqvS85E=;
        b=ZfIzT4uJUyXszC1PejazGbbJy9ZfuuqgRU00ffqEsHqBscfHboYBlQfcEx/GvTKrKL
         nO7WjAgBaQK+hEaBlfotfXVgEyLPgF9SL3mj5X5yXrE2/NnqydSLg0DFaId4tsQ/Et+Q
         eHK9NxeExmL5TW0G4d7DlfKItNCNlJWMQyYdamSPgW1iN11IQATYwKBpXA19jRQuGYpi
         87CT92oHqDB3KN39zKdcC2Yl5QwlQkCZnT8CvB1jPw1EOd6hx4Ph7vuECtNmVeXpH79Z
         MD0KfTihv67jHj9YGNx6KvkKVcFaU1Qil/Rwyxg3CslbD/QtcJpyKAppNsvk+ZIjhk/u
         I6eg==
X-Gm-Message-State: AC+VfDxTCuSQFCEGrldzzw1z/hPeizctiISh1X4ZkhudI3MkAFKDpF4Y
	ech6ZcC/ue+1u+60qPdenFE=
X-Google-Smtp-Source: ACHHUZ6UHeED6U6eKlOwaw4bx29hWRIoZDzUQcRn6Dvami2RPRMM3kXXsR7Ajf+NHTe57ksDxSsz/Q==
X-Received: by 2002:a05:600c:22d2:b0:3f9:b297:1804 with SMTP id 18-20020a05600c22d200b003f9b2971804mr3192150wmg.17.1687261873544;
        Tue, 20 Jun 2023 04:51:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6917:b0:3f8:fa9e:5fa0 with SMTP id
 fo23-20020a05600c691700b003f8fa9e5fa0ls233992wmb.0.-pod-prod-06-eu; Tue, 20
 Jun 2023 04:51:12 -0700 (PDT)
X-Received: by 2002:a05:600c:2050:b0:3f9:b773:f8fc with SMTP id p16-20020a05600c205000b003f9b773f8fcmr1294438wmg.26.1687261872186;
        Tue, 20 Jun 2023 04:51:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687261872; cv=none;
        d=google.com; s=arc-20160816;
        b=cY9EOitFqWQhrumKbubUxxFldzFWMnqyqqvU3caJREAsSZHOAsPlma1sDPKb+Raas5
         Lz9nB9gtuRZpdanFMKhn6ISeVZFRB0a0k0PCz2091QXFLYOVnDZoudorU96Qj8/9Rxb3
         yzyHbtEB1cPHRGo1Q/x8yt4sw8jVRjtwtCU0MrZY0M55QJk65yZ3GTnipvkpGzzpkguO
         QJLGhEGfRv8XsWqT7F77sBjd/zyRW+s+fBq1Iw7OuvM9kRj7KAUW/dx/FRThnctZKAx4
         47jrUf4UAWNACJHbB4dccoFv6ctL2RtvwVH/eAfXppioS5tDj5WYMq06D/COIWGWF04q
         s6YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Uk/ZJntyyMN1aW63L6PViu326GWnEG+0qzLApQJoBK4=;
        b=Qm80EB+9LCazwTJXvyos8+YJl3WeoDpbUAN/4zayd3DORvYqP0ysqlX2wEJmmoitz/
         6nkxpeQtTIGQEWgrqsYPSFGJYRG/mFHkWP79LSR64NzYhvX5iEqXeZY2IMu7sEbaApHI
         EkqJsEK/RK98V4rrN1mnYnRMZxwuwLhclYq2NiEjG5ZwIFhz+JrJgZGSF/koUd84ZA8r
         b3COi8g3TOF+SElczysVuXbVTq3HPBUTOVRyYvdOE/WzPHWn5dBQ3xC4JnmsEZoADHTg
         RFdd2kIhcfPT5O0ZqDwW+BxmWV4MnCmjNVAxlGuzLOmKTDMtEQm2bjb3dUvYzaCrf0nn
         fWhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=3YLv+I26;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id fm20-20020a05600c0c1400b003f90113f69csi134468wmb.2.2023.06.20.04.51.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jun 2023 04:51:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id 2adb3069b0e04-4f8735ac3e3so2713272e87.2
        for <kasan-dev@googlegroups.com>; Tue, 20 Jun 2023 04:51:12 -0700 (PDT)
X-Received: by 2002:a19:2d58:0:b0:4f8:5755:5b22 with SMTP id t24-20020a192d58000000b004f857555b22mr6731320lft.27.1687261871236;
        Tue, 20 Jun 2023 04:51:11 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:8530:a6a3:373f:683c])
        by smtp.gmail.com with ESMTPSA id d22-20020a1c7316000000b003f80946116dsm13216151wmb.45.2023.06.20.04.51.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jun 2023 04:51:10 -0700 (PDT)
Date: Tue, 20 Jun 2023 13:51:05 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Taras Madan <tarasmadan@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Jonathan Corbet <corbet@lwn.net>, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Catalin Marinas <catalin.marinas@arm.com>
Subject: Re: [PATCH] kasan: add support for kasan.fault=panic_on_write
Message-ID: <ZJGSqdDQPs0sRQTb@elver.google.com>
References: <20230614095158.1133673-1-elver@google.com>
 <CA+fCnZdy4TmMacvsPkoenCynUYsyKZ+kU1fx7cDpbh_6=cEPAQ@mail.gmail.com>
 <CANpmjNOSnVNy14xAVe6UHD0eHuMpxweg86+mYLQHpLM1k0H_cg@mail.gmail.com>
 <CA+fCnZccdLNqtxubVVtGPTOXcSoYfpM9CHk-nrYsZK7csC77Eg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZccdLNqtxubVVtGPTOXcSoYfpM9CHk-nrYsZK7csC77Eg@mail.gmail.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=3YLv+I26;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Jun 20, 2023 at 01:45PM +0200, Andrey Konovalov wrote:
> On Tue, Jun 20, 2023 at 1:33=E2=80=AFPM Marco Elver <elver@google.com> wr=
ote:
> >
> > > On a related note, it looks like we have a typo in KASAN
> > > documentation: it states that asymm mode detects reads synchronously,
> > > and writes - asynchronously. Should be the reverse.
> >
> > This says the documentation is correct, and it's actually called for
> > writes: https://docs.kernel.org/arm64/memory-tagging-extension.html#tag=
-check-faults
> >
> > Who is right?
>=20
> Ah, right. I did a quick google to check when I was writing the
> response and found this: https://lwn.net/Articles/882963/. But looks
> like that cover letter is wrong and the documentation is right. I
> wonder what the point of the asymmetric mode is then.

Maybe not as strong, but asymm mode makes sense from a microarch point
of view, where writes are always committed into a store buffer, but
reads can only commit when the data (incl. tag) is available.

> So the current code that you have should work perfectly. The only
> change I'd like to see is in the documentation.

Something like this (or more?)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/ka=
san.rst
index 7f37a46af574..3c58392d931e 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -135,6 +135,8 @@ disabling KASAN altogether or controlling its features:
   fault occurs, the information is stored in hardware (in the TFSR_EL1
   register for arm64). The kernel periodically checks the hardware and
   only reports tag faults during these checks.
+  Note that ``kasan.fault=3Dpanic_on_write`` results in panic for all
+  asynchronously checked accesses.
   Asymmetric mode: a bad access is detected synchronously on reads and
   asynchronously on writes.
=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZJGSqdDQPs0sRQTb%40elver.google.com.
