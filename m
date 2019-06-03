Return-Path: <kasan-dev+bncBC37P2UJRUBBB56M2TTQKGQENPWLQNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 0933133189
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jun 2019 15:54:01 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id c79sf6961oig.8
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jun 2019 06:54:00 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YL+MT+IrJbsW9pLux+GJIoOP0uVaLEhkuUmqPK2bIyo=;
        b=nYzz1cU7GtK7NKhfPWvN3UOeSpFZUz44aA59gugyX02Wi91EkYk+0eV5WWA3zmN699
         HNrTbgHEb84PUJKtjBEEkVxI3OAeBD/KrXJ3Ex/kpZn7e8IhBuklS/CzAvtKBLnCjF1+
         5G1kHtmrzur+V1GU4nSQzZuI6cyboHoe6cqnsmOnL0+NNYZO7LrzxNcT6dxXBSAtPZ2e
         HJnbAlG6vhtBdES/6CyyfulxyS4fdQQoK+pEqNBX6yH63VzgXZSfyguym8fZwZZU8LKP
         gyQFqaHUyCg7gl5E2RCg4Zt13DIbWLlnY9c/S69zD+8P/pMdtTdSsN8Jk1sBol6Vs5H6
         xfqA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YL+MT+IrJbsW9pLux+GJIoOP0uVaLEhkuUmqPK2bIyo=;
        b=HOjA32HvIrKbWTaDBpvWD51K5lEBSRtwGPq5izhWtiN1Q2+9OPOlcxsODJIMCDuMQO
         dUfUlriATD9qLrVRymU/o/7h0iGWo9cK1ZzVZ20yilJEUkwfxJeGHmhvQSOwBlFgbPPt
         0gIkZB8kSfMesBNd2JN2VfTBKx7GtLrqJHetFThoM4dWEqfO+oFlSJvfa9r0sKyB6Qb1
         oHi9WBExFFibM/efmF4CPXKmLKe5+lE3RezHCQAUNfSzOAWJdPP47jhwSb/iopehLVcF
         OxT4fyQSFL83nmIXdcpe62nwCpgLTvU8WW0poIb82olam18bmNdmNLmoBuhS144eWLZf
         RO8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YL+MT+IrJbsW9pLux+GJIoOP0uVaLEhkuUmqPK2bIyo=;
        b=NsEIrI9UsWc73LvB+zyvgIS3ygs3Q5isR7bgFl+JsZT5JXUPYL3du95kJ1F1wmSB0H
         IBdJjocZ/D+oyY4KCoRBr+wgjhoFl8JrXdtc+1hQ9lQonlpOlpUulRMUVQ9qejabL5KC
         GCsEMlevgpKyJO5qeMR4OjItoAoX8oZvUWE7wEM1so/0qA2zsHGnjiJcqAvSDZgFz/Oa
         0GZzMJpxt+cbUhTmLREgMlrXgKyVwqBoThzwbosfaDTRG3EEsGI+h0B02pXP/eN7niYA
         Hzs12yQcqmTHgr+hKWVFJUejH0p7lduH7jeBYwiEtbCymjZrIaZcH3RRzVP5/xrS8Ql6
         lhmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU3Wtof8SWO3GbF1QzzZC4vkU7Lz8cRbRwBRBh7sPdEz/EVOMAP
	erAiCq4t37mh7cskMRcRaSs=
X-Google-Smtp-Source: APXvYqy7uIMUiHQzuLHFl2XHsy+wIAoGaPC4QoULOjVdBKiRq4EZDMIPUgwqAfEsK1Jnj6S4NxojYw==
X-Received: by 2002:aca:cd15:: with SMTP id d21mr1007013oig.41.1559570039628;
        Mon, 03 Jun 2019 06:53:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6244:: with SMTP id i4ls489918otk.8.gmail; Mon, 03 Jun
 2019 06:53:59 -0700 (PDT)
X-Received: by 2002:a9d:7408:: with SMTP id n8mr1256463otk.324.1559570039222;
        Mon, 03 Jun 2019 06:53:59 -0700 (PDT)
Date: Mon, 3 Jun 2019 06:53:58 -0700 (PDT)
From: majek04@gmail.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <07a7e3d0-e520-4660-887e-c7662354fadf@googlegroups.com>
Subject: Kasan for user-mode linux
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_1120_1666742943.1559570038590"
X-Original-Sender: majek04@gmail.com
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

------=_Part_1120_1666742943.1559570038590
Content-Type: multipart/alternative; 
	boundary="----=_Part_1121_1980796598.1559570038590"

------=_Part_1121_1980796598.1559570038590
Content-Type: text/plain; charset="UTF-8"

Hi,

Is there KASAN for user-mode linux? 

Alternatively, is would setting CFLAGS="-fsanitize=address" make any sense?

Cheers,
   Marek

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/07a7e3d0-e520-4660-887e-c7662354fadf%40googlegroups.com.
For more options, visit https://groups.google.com/d/optout.

------=_Part_1121_1980796598.1559570038590
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hi,<div><br></div><div>Is there KASAN for user-mode linux?=
=C2=A0</div><div><br></div><div>Alternatively, is would setting CFLAGS=3D&q=
uot;-fsanitize=3Daddress&quot; make any sense?</div><div><br></div><div>Che=
ers,</div><div>=C2=A0 =C2=A0Marek</div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To post to this group, send email to <a href=3D"mailto:kasan-dev@googlegrou=
ps.com">kasan-dev@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/07a7e3d0-e520-4660-887e-c7662354fadf%40googlegroups.co=
m?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid=
/kasan-dev/07a7e3d0-e520-4660-887e-c7662354fadf%40googlegroups.com</a>.<br =
/>
For more options, visit <a href=3D"https://groups.google.com/d/optout">http=
s://groups.google.com/d/optout</a>.<br />

------=_Part_1121_1980796598.1559570038590--

------=_Part_1120_1666742943.1559570038590--
