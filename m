Return-Path: <kasan-dev+bncBCP3N6V5QUMBBENXS67AMGQEJYLHAWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id ED13BA4C795
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Mar 2025 17:40:51 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3d3dee8d31asf34938095ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Mar 2025 08:40:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741020049; cv=pass;
        d=google.com; s=arc-20240605;
        b=fYi/Rqh2k8R4sfXe8czgEwx3SXp1b0WgN7CSqHcN474Ws6BYwyFr+oVRi8TvlrSe3V
         bmKzSBEQaXEZcW2MTZIpI565Hbr3niym/5T1Qm+W2Wtd3GFNz9kt5new/SVPi+OTzyPH
         dMqMybylw5WrGUrNAVa6PNUvA8kYAohG1MuTyL04dd48BSPsDpkbsUpAc1JUgP+I0Ihd
         elbf004CDyPS2mz3deJPTltjbTROkz+AW6KanKn0Bf038fSN9iTp1v3lAThQY5Ec6dcU
         whGylGPN0fG5y/yfKsqB5nWZ4hXXAUa+w5CoTFrVH1Z0nym1KaHzLGP8qZ6OkxZfB98g
         +qrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=78h9BixA0g4gk/AmX8MbNgo9fpyaFxEy44zASAAe45M=;
        fh=rWDSQ1HBrdP6VePRS856k9Qw/ifNWDLjhdWTvUWRxhw=;
        b=ExlU3zerXFMTLxf6pGw53M3Ml3/LvUrv1xMOrZTvLg+M+h9mWWHTI4ZKrbcRHaNbiz
         dhzyOTsRcVbf3MMxubroosg0fKMzQApsF2YazT2Rjr4odfiLJW/0x0GHn+c8SJLFTMoR
         c9D9w3vT8jb1r9lviq3+mxv/CcSYr6xMllnHZpZhm6WfZ/44pLbe2FuZhqvWHtbmLU2K
         nAZi6rlz/yEsIIdZZMTuxZMyfbvBROJlVdzmcY5EhFBtGhihC7ArAl9dCP25GOpFXt3O
         4CGc1x7A90ZeLk7MkURc3I2b5Ga7RmwUXVzzvWyXQkA5lgv7G0bWJdbJ0OnO5L2MsUE5
         m++A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P07XBrFm;
       spf=pass (google.com: domain of gracelauhkma946@gmail.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=gracelauhkma946@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741020049; x=1741624849; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=78h9BixA0g4gk/AmX8MbNgo9fpyaFxEy44zASAAe45M=;
        b=jweUBv04Oc9igAHuKoahHzJPRccZ7OoetMO+mXKXtx+Ohonw+3lUgUOn8Zd3c2O4uR
         XU+WgZw0pNPBV9WbkJpy5iSHJ7YF8nNRTyw1LHXD62qU9BM5p13wpFZR1/6ng7HFeRIC
         ETDilSXfueroeq7yM6bliyXhyMvpaYB+4Vd3xXLgIxW23PrbMuc+74fNv4PIycdNHpWo
         KBzkP10W3iE7vA2I3RZO5OZ1/e93uqUYklpjDRZ3Br9dxOvNaCicnARlQzHGoWSkDQ79
         A06VwGWaON2EgptNioSlfNIiuVGu76Jw9tb7aeK9rOV9juBj0Z9jHJrJSVNXrUQvC/K+
         7wTQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1741020049; x=1741624849; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=78h9BixA0g4gk/AmX8MbNgo9fpyaFxEy44zASAAe45M=;
        b=l/p4MXCmahp8dgvbd95XaLSLcla/9kUqDkS24EKGT+uJ+QJpq0ijTBUsfggUVt8q2H
         MgfW5a82gpD0P3LSCLv4dodE9WbkjSYi6V6m8lz6Syv8ObG1haR2Q0c+8I1vAJwXeaFH
         WBVuQjDPe1hDoCUhBZQgSSIOWM8FSRDC9wenGiI3z/rsAlOaaRyZCEKn9zdKVLv+h7pU
         i+sk/ExKA/A8lZvJtOXr+8sfg4Udyf/CXan1zM53+5AoKJkeAeF+dDe19+zBNvqxxB4+
         x0qMiEtWxlLPRls9e7lJxLBvkWZ3hiT/L6Ld8r7l0iAwtG6i/cex80Nf3TxcshdPlKs7
         EcIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741020049; x=1741624849;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=78h9BixA0g4gk/AmX8MbNgo9fpyaFxEy44zASAAe45M=;
        b=vO1U6DMmVQyqQ+fWnJgckp9GRAPmYrqzgENiHwrQbygGFB2x5mDMpK3ZaQQQj8CO0Y
         PqGUA7rUUP8l+uX1UuRG5/fqLfctcStgELY+s7Cd4b8bqzlBdiUorNfFGnxePBzCPCAm
         7MwY1qi42tjpd2gDu+F84f+QrVN7yhFVU+NzJ2AFNy6rmtFVq4D73+KlAZfRpCPv0doE
         n08dFjQV1OQa8SWnNn3fnaHrzXxPiT8cjbuMdbVp6xX+rt9vN8GB01nPmAV0SVZFnMVR
         sM7jQnLuIZfW4Ybv+7AUzE7uHq1bghIR6E3wdZlG0ZObmrdcZZlKy44KG5/37CmjMFV3
         chZg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUlW+s6B8d1pvoXT/hHLO4fsFxoxaDe7atUbcBMwuxnAJagqpugtm0UW0mBz45EMK4p2Lmexw==@lfdr.de
X-Gm-Message-State: AOJu0YyeO2E4lP50P+Vjp7PJpOBZBOh0//sxtaBOU1rq4Wqv5B6O4Yw7
	JofhWSrLKPVXEb4YPrbJUpaLds7fq/WIpEzkwKjz9LL+IXKFl6ud
X-Google-Smtp-Source: AGHT+IGj4sOmP7gtDNfUV9X6e0owxmNsi8fq9cHUBmaYd4mUNwj8PLFdDZEKrjXhIHh7sk0L6wpmcw==
X-Received: by 2002:a05:6e02:13a6:b0:3d3:d0dc:52a9 with SMTP id e9e14a558f8ab-3d3e6f3f48emr123924725ab.15.1741020049272;
        Mon, 03 Mar 2025 08:40:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFDSpK2s1m9ajwYIsTmU5PjDjECwwM4JrmsFmXT6jQ9vg==
Received: by 2002:a92:c9c8:0:b0:3d2:af50:1124 with SMTP id e9e14a558f8ab-3d3dd2316dcls19228785ab.2.-pod-prod-04-us;
 Mon, 03 Mar 2025 08:40:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXkg7WhKzIGzIr7ytkjmLDyUChpv3ihmpyY2DZOmp133YRD/TFZXyK9qE9BBInhm9mEjYVXfLgesi0=@googlegroups.com
X-Received: by 2002:a05:6e02:548:b0:3d3:f4fc:a292 with SMTP id e9e14a558f8ab-3d3f4fca3bdmr79781585ab.12.1741020048579;
        Mon, 03 Mar 2025 08:40:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741020048; cv=none;
        d=google.com; s=arc-20240605;
        b=Gs2niiGNszxlCmq4439o+jq4WVubI09SsxbMRRKftWCWhE7klVEAP8FNd/ezM4l7AP
         aHBbNcRpoJ2j1Kfvzng7UDRVSQDBMEs+eiwYOhUITbW9gLj6+k2L4iZnIoHOcW3iRnxV
         xEk1kMGjKimYs5iH+5ewj9mllznCYuynt1TfPacUknuaWy1oVGwOk0XzPrZnD4ZQ4S6f
         3/g8G5gS5jJgoeZPoNxCMnm9HeKOs+Li307I5ZX2osJYab6lI1UHitkcw3PXzCQpnlmc
         Un5lvODRkKJGOg/Ntw36k90zXG1WYTiCj3+70OGXcJqJBj281KnTcez0gZ0yIpD3xAYd
         0GJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=Zl17lTp5FgcXK9t/AVYcs2m1/KoHceDm+XRAxg9YbcE=;
        fh=JYhl6ZyE2w8OamZIEn5Bs5LqIUskk0FjUEr94q+tj2s=;
        b=JkjX7fErSSF2a4dyPMQ7P79FISjut9H5wtSDvPv3U0jK38W6u23kpeeQ2X7rr7JSaG
         uovGOxnAI2OewUilGGyFOR8uI5zVosaSEUQlVVTBjSPdEweJ1D0Ve+jvmNR8RVJagxPS
         SFJCQbZAcRyFxUOUcbm5XDMh68/ItZA6iUBbyCHmSaFYgszy3JZacRiia4BJKbFCaWHF
         0nP4LgI6GoL5+64D2cfcyJTYOg5Ib//qLPxnj5DNSjLpJydShbDWtyM3yq/kQ7XZ6HM4
         3Kp9TzfMAFrFHMRBqLjsRIzz8+25N3feXIdQsKbtTyc4ZStqojQw8SniHTWzJ+HLbNpy
         ZMwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P07XBrFm;
       spf=pass (google.com: domain of gracelauhkma946@gmail.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=gracelauhkma946@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x72b.google.com (mail-qk1-x72b.google.com. [2607:f8b0:4864:20::72b])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f061ee598csi814128173.3.2025.03.03.08.40.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Mar 2025 08:40:48 -0800 (PST)
Received-SPF: pass (google.com: domain of gracelauhkma946@gmail.com designates 2607:f8b0:4864:20::72b as permitted sender) client-ip=2607:f8b0:4864:20::72b;
Received: by mail-qk1-x72b.google.com with SMTP id af79cd13be357-7c08fc20194so810558885a.2
        for <kasan-dev@googlegroups.com>; Mon, 03 Mar 2025 08:40:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXHX3sqfkkeaUY0p2tzBbp7DWJkyvS2jSgmrewKo+SkpX+qhvCQ79aotJe8X4SC0GREqRRZy9fn/8Q=@googlegroups.com
X-Gm-Gg: ASbGncsszZ6Zrr1aLZKvVjbGfk/5kuAK1c+VJaKgQtaDRw5SNRxx4IJqOt5qYkZc8SU
	/cWAquh1cwOc2ocNCUaBTlTwQkhgu4/mnpxD0SIBusZXzSMpI6n+Crdi1K1v/wtpdE/b540wZEM
	4BqieDsrHksI98pUSeX9SX7Z+5ONiH
X-Received: by 2002:a05:620a:294f:b0:7c0:ab74:eefd with SMTP id
 af79cd13be357-7c39c4c6d14mr2083111285a.31.1741020047473; Mon, 03 Mar 2025
 08:40:47 -0800 (PST)
MIME-Version: 1.0
From: "Ms. Grace Lau" <gracelauhkma946@gmail.com>
Date: Mon, 3 Mar 2025 08:40:33 -0800
X-Gm-Features: AQ5f1JpW1iGs-pSwoCqaU33jDwxUy34L-CpcP1pReLoAvzpM6LaHAWbzA-ZZifk
Message-ID: <CAAOTDwPDJADZhfHKTmnGZ3Wrz+Scy33yYdsN_MwY19h_uHvQug@mail.gmail.com>
Subject: Investment Opportunity....
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000007a2276062f72d1c9"
X-Original-Sender: gracelauhkma946@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=P07XBrFm;       spf=pass
 (google.com: domain of gracelauhkma946@gmail.com designates
 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=gracelauhkma946@gmail.com;
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

--0000000000007a2276062f72d1c9
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hello,

I represent a client interested in investing in your country and seeking a
reliable foreign partner. Please let me know if you're interested, and I=E2=
=80=99ll
share more details.

Best regards,
Ms. Grace Lau

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAOTDwPDJADZhfHKTmnGZ3Wrz%2BScy33yYdsN_MwY19h_uHvQug%40mail.gmail.com.

--0000000000007a2276062f72d1c9
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hello,<br><br>I represent a client interested in investing=
 in your country and seeking a reliable foreign partner. Please let me know=
 if you&#39;re interested, and I=E2=80=99ll share more details.<br><br>Best=
 regards,<br>Ms. Grace Lau<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CAAOTDwPDJADZhfHKTmnGZ3Wrz%2BScy33yYdsN_MwY19h_uHvQug%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CAAOTDwPDJADZhfHKTmnGZ3Wrz%2BScy33yYdsN_MwY19h_uHvQug%40mail=
.gmail.com</a>.<br />

--0000000000007a2276062f72d1c9--
