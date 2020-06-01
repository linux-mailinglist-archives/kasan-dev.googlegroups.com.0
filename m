Return-Path: <kasan-dev+bncBCI7LDNNRUPBBHE22H3AKGQE7DLT3KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BE511E9B02
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jun 2020 02:34:37 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id m17sf4428514pfh.1
        for <lists+kasan-dev@lfdr.de>; Sun, 31 May 2020 17:34:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590971676; cv=pass;
        d=google.com; s=arc-20160816;
        b=vuKJE8H5aOy458hnlozsLoSPI0MBHJBGRN5iOmiHViq9W/5BKVe/ckJdqbBl64e6gp
         w6L+dwRuHyc1LUf7FBDsx0fPBkoXyICRY+jzrU7lkpmJNSOT3/X1uST1DXmIB1x3l5yX
         cpvIFtSVgnrIhWD4PBHsWgTTnPNEHv8wmcHAWtffPDWLcPI/JXbeUpsS1CvuG21mpmNJ
         xlGuounCr9lBmLoDSYmt3M7ZBmV9majLQqbwnTTzY4b8EFzLvyA6KDBAOBW2HLR2wUhZ
         RmAEgl5w+3Lx/gtXixEdWa5KyrWbiiCKEn8RPkd373ADdfEhqGJ2OlGtWpE51TAOBxnc
         c9Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=t4pm5c7B9rqlCEw7CjVeZ9RFgkpNSaAn2KCl6BMyXkw=;
        b=UxVEaU3B1lWSiCm1DLCzgLDK01AeznMRGcHmDwOrEVHvxBZYO608WiKWdEVSFkAEMS
         U719VxygtImbsHKQPW9b+f8AafmiU6AteEI3yHfgWirv49UXF5RBF8/l99/riuZGJHI1
         EyrX3GwTavFmEXDI4f8tXTAqoeyPVBlc082p3Rg2lfoE8nNHmbckAhj0uB2JsgIOikY4
         TO3A0SXS50al+2Kx5SOgQT3Nfa2IoqMl4vrVpq2gg6k+qryKtWK81zOtXxHVT4bd9h4X
         FRdMm7vWnSr1HN7yQ5dF/B3eC3BjjIm+yjiY6dUSoyNmxJuFNiueHWMZtXK5rfUSm5ze
         kmLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=S52nluh+;
       spf=pass (google.com: domain of neswgood@gmail.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=neswgood@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t4pm5c7B9rqlCEw7CjVeZ9RFgkpNSaAn2KCl6BMyXkw=;
        b=dMyqDhRfocSlqAZ5aicCcKUZFrYqPUOBd8IlHMsrMB3qAgjHfk7BwUDFPMzsFY/bvo
         ZqrD1agaV3jpLFuzRkxHz4zcqlRAW1pQjMcRWB0AK7QtW56vsVygvGpfUoFmYlmOUf0p
         CXB1xCarN1D/fDF4iYSQWvgx9wZjlE/3Hif7F3iRRqqwNPGu1eo+Jl8aeSQ2TJ60x6wQ
         kojvnso//1OmbmWqiiKNxxpy/fWqKK8vXhqXVnw/MZjp0CpChfjkWUkEamEftq58dvIJ
         E9iwgUf0kudOuFjvT4wRkb6qKWaCxSIcFYt6hHl+QiyG9b+tpASuRF3Xff04hX53fk7S
         tHag==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=t4pm5c7B9rqlCEw7CjVeZ9RFgkpNSaAn2KCl6BMyXkw=;
        b=GZ8KgwmMppOtCxqkNImo77y7XabbHFnqpcuLdzBjcauuS+Wrv69FvGkxLzk9aoOYaR
         mdUXYOcylSKeJTboibjGRv3PJsMwcCAJVQYwlrpdrwwGflEoL8t1xJMVki+S86s7C1sW
         wn6FLD/VclYQsqt0+cngSahywW9z3X9Lrxz70tf690huvwRCmdeZ6PAl6hzhRTykncG0
         KRH2DG8ZQnK3ZA2RraywIJCwZcEqoW6zCQ7HxG1FXfG/P2HVfphYGDzhVRbk5CSps+8A
         Qhx2sT9F3ATOy77IUcjWhGuwjNHODiq0rDU/WRe/Zfqlno/jhSvVeKgoEbBf5bB9WXRv
         Ke6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=t4pm5c7B9rqlCEw7CjVeZ9RFgkpNSaAn2KCl6BMyXkw=;
        b=pYni17Gm6AoEcPsLb4GMbTN7/0W+XeVfWyMkwL0FwGZLHGGFT6pOxseSwu+oC+PWVs
         llDjWttWnCAkI6K+Q3+D9QzjNv1HIN4UYcwZhEr1Ke66tz/w+g0kMIGQx7Mpgcz3YhhZ
         t3BHRm8fDUlFbwGisJw/kz2m2OVXyML/y9hkakk6kpCA0JefDFnD/qdcRREhE8FTiMgR
         cwWAYATlFw7Sqp99vuvzYUCr2hATUkD5cKAsADtkyQGzHx+yvpv2HijS6AZ5rUl61sOs
         8xcoNUeuGlCvS+bH4H+oIMQVH/WxYVb9WAzWbIBImfgW0+qGhcxRZqontO6mOp4klf8e
         3S7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331lO4Ekt60sAS4hI8hQd6N2wzXgG4XCCk3JbPSnyFoUxOZ3uXA
	Ilfr0XGweaf/pVTUReQ85sI=
X-Google-Smtp-Source: ABdhPJyL8g5FT3+7kC1bgG3vir+e+Htj+CRdeA/oWE60cWT0CvI9MEs2QbVwSuyPq8iYVN1sTxP/jw==
X-Received: by 2002:a17:90a:aa8f:: with SMTP id l15mr21718910pjq.211.1590971676315;
        Sun, 31 May 2020 17:34:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d349:: with SMTP id i9ls5805526pjx.3.gmail; Sun, 31
 May 2020 17:34:35 -0700 (PDT)
X-Received: by 2002:a17:902:a414:: with SMTP id p20mr18623521plq.333.1590971675902;
        Sun, 31 May 2020 17:34:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590971675; cv=none;
        d=google.com; s=arc-20160816;
        b=nwDAMzU7yOGw5/YYAMu1pVMSO3hVsxmHdnl4mGTSrIrHU4nm38tq/ESPtsUCyDTkrw
         s8XkXbMvv2rfC8dCsH09NK6CFIEiteibfUc1xeZDVHGKBqpjGy5kyi3LOvEWd4CdnRiO
         jR46QaJqlcE48RN7ff1e0cs7IUfejubnRciYssv47xGJQbjFjZe685sXS+9REq76mm53
         yCGbPUjVgMEsNO/1UeJldeSNyDH0xJ4e2JNyfMCNqpjgf/ubot2kDRvYifK9VSfN4OQz
         a4ndKSDjFTPvzLpN4DUrABLPV33w6ffR8CTHsTtpg2G4hzrNnWRtTaud7k26r+q4BG2l
         oJag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=QPyFeV2cDELhd9dc6jn+njAi3ogL1W0LM6bYSp1zceI=;
        b=iaZWB2+KIztsIzPlutWyar61scA57DfwZTxWbj11iyKBu/+gw0yBdEgReAaGb8YSZg
         bgE9VydYr798fgLc6pjOGfQy2cVvFTr39V/5cq8rkwMN42hRIOYXCX1rXcW5UZ1QNyDv
         jtr5hqcpT10jScucTg95DzX5rPMwwuSkdbQp1PniLbOM2tSuN3El+SropdrAh6nCY4/G
         yOd0W6n2tXIwpQqqCWDngowvSgkYpsv8ElyX83H7ctsMe005w+f40Aj0kzVfFxjq3cjn
         t/P178a8K2wbq9bkxIBFxnSzBg8ESZ4Sv1OvMOZoYX46Qu7AiQjZysTT0Ogwz+SLIfto
         y1hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=S52nluh+;
       spf=pass (google.com: domain of neswgood@gmail.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=neswgood@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id l9si126647pjw.2.2020.05.31.17.34.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 31 May 2020 17:34:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of neswgood@gmail.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id k15so3190789otp.8
        for <kasan-dev@googlegroups.com>; Sun, 31 May 2020 17:34:35 -0700 (PDT)
X-Received: by 2002:a9d:32b4:: with SMTP id u49mr14949509otb.304.1590971675594;
 Sun, 31 May 2020 17:34:35 -0700 (PDT)
MIME-Version: 1.0
From: Marvella Kodji <marvellapatrick1@gmail.com>
Date: Mon, 1 Jun 2020 01:34:05 +0100
Message-ID: <CAF0CuhBr_a7+a5kZMGcJALC+o2mbQ6uUse7rgfn3_-Nrefj4xw@mail.gmail.com>
Subject: 
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000092540f05a6faf50d"
X-Original-Sender: marvellapatrick1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=S52nluh+;       spf=pass
 (google.com: domain of neswgood@gmail.com designates 2607:f8b0:4864:20::342
 as permitted sender) smtp.mailfrom=neswgood@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--00000000000092540f05a6faf50d
Content-Type: text/plain; charset="UTF-8"

How are you doing

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAF0CuhBr_a7%2Ba5kZMGcJALC%2Bo2mbQ6uUse7rgfn3_-Nrefj4xw%40mail.gmail.com.

--00000000000092540f05a6faf50d
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><div dir=3D"ltr" class=3D"gmail_sig=
nature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr"><span>How are y=
ou doing</span></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAF0CuhBr_a7%2Ba5kZMGcJALC%2Bo2mbQ6uUse7rgfn3_-Nrefj4x=
w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAF0CuhBr_a7%2Ba5kZMGcJALC%2Bo2mbQ6uUse7rgfn3_-=
Nrefj4xw%40mail.gmail.com</a>.<br />

--00000000000092540f05a6faf50d--
