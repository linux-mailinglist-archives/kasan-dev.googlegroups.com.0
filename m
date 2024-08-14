Return-Path: <kasan-dev+bncBDO456PHTELBB7GA6K2QMGQEC4UJARI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 68BC4951AB3
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 14:18:08 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5d5b62ee8b9sf6426358eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 05:18:08 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723637887; x=1724242687; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Wm2/9rbzxj1n44HQGutGsCh9XZF9UziZMgPDvgPttpg=;
        b=ZE0FCR8F1LfuTnRuui7jln1MecElVuTttOkcJjV7fSXID5Pe3QFuOolXbl09JGGEn1
         KwJ8iE/onIl6dzZt+/R+S1VnHFkjITd9DMYLS8Ig5eidmqMMiDNhTb4FHCbPkhWn8oVL
         lFVbP7bYnrUF5gd58u6J4WV4ZrJ/95XBzTnvPneqoC5ABU7RUoBYKIM5ui9lbaRZAajt
         i/2OH1Sq34nLvv61YfCWTAESwl6y6+ugqVwF5sVRpS6OIC1B8QjGOJmRljTANgvffHUw
         Bo8VLPPO0cZ9Btqw3lvh/mE/Kk1tO2btr9ZUiZuK3LZ2YKyzIgzzkd1Ej+nHtHWQx1CA
         ktRg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723637887; x=1724242687; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Wm2/9rbzxj1n44HQGutGsCh9XZF9UziZMgPDvgPttpg=;
        b=KVr02bsNhLGm8WelpVnTtrSMzc5gkvIIkgPy4zo4aLLmg9OP887Ofaak7QatjczH6Q
         k/GezldAb9R+xiQ+T3q1YrYvcdiYCk9p+lBFPxUDFJYG3diP2nJzbJACvRF3i2Zimco2
         g8wz3teRbFJdMUDfSH7XBS3Iirl42bNC4FhvrMD0+5/eS0II7RBgRrl6s9JK4TPcmBeE
         q2sM3LcLxpnPYhmaPKc5SHVNUGznHH9SgINZSygsvJCE9nw46CVVFh/i9baVXrpAJPQT
         wsZN1W2hCPwRFIfimwG3F9WTiSMaT2dknSi1jUpcZ3EJZeuZe16ezdKy4TZ8TvJcTBKL
         qlbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723637887; x=1724242687;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Wm2/9rbzxj1n44HQGutGsCh9XZF9UziZMgPDvgPttpg=;
        b=xDz5dV7tGMR1VWzX+8VGuYjIOBMpZ+5MB20oL89DXlNqgTvgFE8/1vF2FEdzMQqg+t
         uIYQxHFjrWjDcTXyz+d5ITmWeBX1+83b6TOtb3yRQ1yCje7e9NJYb1XWJ/GvtQ1gLL1n
         CaIR0x3VAjCYmS9JT4kHQr4sMgf+hax8d8DXrPYnetoaWPYZPyil2BMQT0ZX1IjoKNLg
         TcENcmo9Zvn8c8GB5cUsasv6iOFyAZooqAtyLhcUoPHa44KGY6R9o9GdAS0cPbyhxFHW
         EwpD4ab0tTdbRV+wRuPG9Ujnkz0aI+JfBweTbK4SsaGvLJW68N/4takVCNZhXrNYTNoF
         /ZFg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCXw2FgeM+aaSRg7h1VetQIMiW2SmCiczL+QvuLFOnRBIcfqwWElyktRCNBdbeThC8TkhRUUU9k4hXF4jRhoK4XynKACMe9Ulw==
X-Gm-Message-State: AOJu0YyCdQtAkeFveH6tovrW3XzXsd1mUiZ3gIRRIndbJgF6SHEOT5wN
	iww3xsimzEmr0ZDvgjqWTvufrdxUnEFsYKojXyBPWk6CtlwKgYBD
X-Google-Smtp-Source: AGHT+IHSdDPQIZKBGuL14GkpFAPjY1eESRWIY37qbUHQdBFxiX0p57MhNiX2+Uk7+kacsVPgANfYzQ==
X-Received: by 2002:a05:6820:168a:b0:5c4:27f0:ae with SMTP id 006d021491bc7-5da7c5cc4edmr3156852eaf.1.1723637884901;
        Wed, 14 Aug 2024 05:18:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d0d9:0:b0:5d5:d5b6:22ed with SMTP id 006d021491bc7-5d851250c53ls1949061eaf.1.-pod-prod-00-us;
 Wed, 14 Aug 2024 05:18:04 -0700 (PDT)
X-Received: by 2002:a05:6808:1981:b0:3db:145c:7bb0 with SMTP id 5614622812f47-3dd218ba07bmr405741b6e.5.1723637884125;
        Wed, 14 Aug 2024 05:18:04 -0700 (PDT)
Date: Wed, 14 Aug 2024 05:18:03 -0700 (PDT)
From: hana soodi <hanasoodi668@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <52304f8c-1878-46ed-937e-5aef10ff3c9dn@googlegroups.com>
In-Reply-To: <9116c690-23ca-4014-909f-c8f059cb6ee0n@googlegroups.com>
References: <9116c690-23ca-4014-909f-c8f059cb6ee0n@googlegroups.com>
Subject: =?UTF-8?B?UmU6IE1pc29wcm9zdG9sINiz2KfZitiq?=
 =?UTF-8?B?2YjYqtmK2YMg2YHZiiDYp9mE2KzYr9ipINin2YTYsdmK2KfYtiA=?=
 =?UTF-8?B?2KfZhNiz2LnZiNiv2YrYqSDZhNmE2KfYrNmH2KfYtiAwMDk3?=
 =?UTF-8?B?MTU1MzAzMTg0NiDYqtmI2LXZitipINiu2KfYtdip?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_102108_760366706.1723637883570"
X-Original-Sender: hanasoodi668@gmail.com
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

------=_Part_102108_760366706.1723637883570
Content-Type: multipart/alternative; 
	boundary="----=_Part_102109_1526675645.1723637883570"

------=_Part_102109_1526675645.1723637883570
Content-Type: text/plain; charset="UTF-8"

https://linktr.ee/cytotic_d_nur

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/52304f8c-1878-46ed-937e-5aef10ff3c9dn%40googlegroups.com.

------=_Part_102109_1526675645.1723637883570
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

https://linktr.ee/cytotic_d_nur<br /><br />

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/52304f8c-1878-46ed-937e-5aef10ff3c9dn%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/52304f8c-1878-46ed-937e-5aef10ff3c9dn%40googlegroups.com</a>.<b=
r />

------=_Part_102109_1526675645.1723637883570--

------=_Part_102108_760366706.1723637883570--
