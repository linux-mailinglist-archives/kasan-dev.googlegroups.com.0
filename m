Return-Path: <kasan-dev+bncBDD2VNNPRMKBBKFM2XVQKGQEAVEBSDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id E13C1AD06F
	for <lists+kasan-dev@lfdr.de>; Sun,  8 Sep 2019 21:27:36 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id o11sf5921167wrq.22
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Sep 2019 12:27:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567970856; cv=pass;
        d=google.com; s=arc-20160816;
        b=BtnPw+SBftMdqDCNFPhmFJ4Xo50+byqDvO8G/Zk4zCUXIytoWlDFHlaotZumcrtwax
         yNg4uRixdtyPjfaIa61fyEmahjj7UdTR9yj7pVFbd/hIt0cOR41F+9ArTqHnJ8bOCyn7
         t9Cz7y+uGzv2dZ/QqTI+laNNz+qiW0tep6Fg+HuCn/Yf21fm9Y1wYi1jrso1M/dtvj4n
         QQ7RCV+56SNrJ1jEhyk7yWtgrJ6W+776bEfwifzGYsTIyJp9Wqim3c7T8L79eQIoYai4
         bkRtQ7o4fIPaJVlEWsXdcu1GZlGRqZTKzyKtAJq7rhnA/pEEc0acfkgHgv7denc9C8vx
         0dHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:reply-to:date
         :mime-version:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=SUAiW02UE+tpwPZQjM6l3s9tXluPGHhuWgTJ2mfBRLI=;
        b=zMgbAfVOP9jxrpFxIfpqIq0YpURYqFMDJNXS/vent0RZ679KmL7GnWmrJF9Qu2nNPv
         VotoBKZitF/9mBMTHq0qaxMsvVulqGu4/rLoWugZk6w6AD5SnT6rVyNJk1r6A664XxUR
         aJ4AN783TaoACfYSq5cg0lnFBCwXVxfK1+o5Jt/057syDEMypQmrZESkb59/7D09fc9Y
         gVigvCfuwx6wDtKpBV3FOFIm0C/WdHPm6HKGoZpWZcYRHp7U7dMIGnE3fdGXhfLkarrA
         oECNd0I0ZkiF0AqHhQxJ0q+C0I/fVXaecv2gWVmoNCGVPXcH9rh45K23TpQ5QnxFLmZn
         YfaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=DkZNJijr;
       spf=pass (google.com: domain of nahwanngaycra@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=nahwanngaycra@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:mime-version:date:reply-to:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SUAiW02UE+tpwPZQjM6l3s9tXluPGHhuWgTJ2mfBRLI=;
        b=tEJEyWc8l6yVCqCu9gSnmR3urRJ5Zc9eBmT9cr/4910bDoqRGKVc/yPJl0bDtDa5LJ
         kGOECQU9BMid4Mqo0A5FXFE2/EdWbZNi8C8qkA0ADNYWuRMX5WcYJOUuMDAYYwx7Yq5G
         bI6bzFjEJkRoIUwPOipRZCSE5NDZQdOA0+A866qDl+yZx/2cZBTYsC4lqg08FOGWaOkg
         M4UtcOXF4nsNNNx0xXbszTxduXNpemijdNjSTo7Qdl0CzFXvYPJJM7VhuCjCEG5YzFOf
         YcTp3T0e+6fq4C65BIIwqp334XHnteV9NxyhwahNXd1wCc+NC3tLZ9XNE7aTu8dOnu54
         /rEg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:mime-version:date:reply-to:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SUAiW02UE+tpwPZQjM6l3s9tXluPGHhuWgTJ2mfBRLI=;
        b=H/J82tjNrn54MU6EZ94adH6NepGbkACkBMuOrKdd4ITTSz5RRB7rkVDaRyVCEC1v6b
         3RnRTLGIIW6qaH0KuQZLz4aYn1ldFwNHEmyecv+j6Y9G1iwnAq6/yVBL8AXJEz226jSo
         d9uPY2ziV3AFL6KAQR9O+GPLo6tRKxvGUGNKInE1KfDdfZ21zg+0CZTmD0/GCjF4sKDU
         el0howZY1pvUiqwI3rA8NWCg1ypo8CBEhF2TIsh+LFlCGyhSSebfMKIh4o3qSatBDf0e
         kfBnPSJoo+TwJyuCd1A3DAOCyMiXnc6UF3q80ZsDD8VHDrLE2914JPzllsmjnw9CXYwa
         u/Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:mime-version:date:reply-to
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SUAiW02UE+tpwPZQjM6l3s9tXluPGHhuWgTJ2mfBRLI=;
        b=jVAkJvZJDWaT6LcBtrXKn4V+legN6x74WahTNZpk7GBAEdbLWk+71HjCya8BSpierP
         Ho1tHxSaVoaD31SH04fxgeqtSSFI0CfUP0vQC0LxD8L0B/2x5w6TsjK8vDRCua+vsGe2
         jihbRYxBFjjCB8Jf3tOE+ywq3pRiipM9wgZkX8bp4CP+0KmMIHb2+JjXoXZPLv4lRtgZ
         jIQ5Rt4zmSV4zif/OUzk72JuXTpAAfrvwBvYl2uH7Ner0iyk3G1/31fUf3SJ5OiYZXBf
         MaQ9JdIsHSxAukjtrF1Zg2P9Wund3qBnpCqxG84kWddtd9aWA04jQs0M15Shu29zO8Ow
         5wWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXFSZ9yeEQ/Qye31ihbXB2UQd4xcLVOiKA5QAS8r8NriyCsEktb
	k5rnutX5o1bKgvau6l+tIwk=
X-Google-Smtp-Source: APXvYqx7sEu/GZ0UwXUNwLHfxN+Nc2onkbhujVKp3R3fS6/q/6kSQ1aDh1v8QlV0izQP/S2V4EJkYA==
X-Received: by 2002:a05:6000:1cf:: with SMTP id t15mr15043462wrx.173.1567970856626;
        Sun, 08 Sep 2019 12:27:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c5d4:: with SMTP id n20ls4298168wmk.4.canary-gmail; Sun,
 08 Sep 2019 12:27:36 -0700 (PDT)
X-Received: by 2002:a1c:a54a:: with SMTP id o71mr16515005wme.51.1567970856282;
        Sun, 08 Sep 2019 12:27:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567970856; cv=none;
        d=google.com; s=arc-20160816;
        b=0kAEgeSsrAqMHOX3wzBmXDVtPclv5nNLhaV9Gfhw/lijhgSSSzVZk8061CMPlPiiKV
         N/iokZ3pN252s15dz+Giwhk3lRru2OhYkDaYYKiSRDIa+F+BP5t/NiSx7RgfcIuVhq5u
         FORSQriZUsCbdv+NPvgYVdQkJuz4I7KxUcHz5/Igxl8HUOg0I61xMIuXLItCgVPTH+69
         aoUGVPFo6mXYUZ7rzTYyMpdmPi1NTq2KWM19Pi8Oa1sDCydvHtrNf3Ic/W7eHo7rFyIq
         jc8mYBD4Kt3D0IAuggCdo1W3WpPA8KMDMSxOk5uvXr+0yZyNylpij2e9YMP3/tcJFMRH
         UlKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:reply-to:date:mime-version:cc:to:from:dkim-signature;
        bh=lEGnAkBfS8zOnVVP9U4x9qLEF67tKBl6KYHOxh2DVpQ=;
        b=EEyF6aIIfFnlVaaiVF0S3QJ0FR/CzizAkmhrMV6u5jzWJu6FpBXl6JU9wZ8gTWwDVn
         2aYUpeh571bvQPMxJkiOIsADSDxbSc8N1f89He3NuoLSBm9WetpqQ7NhK1P3y2lG1PaI
         rV60ifbH2MS6bRLVtJw1MAzja5zFkH0ZgvZFMlO7/RyCcNMqpQD9POXJTvjjd5nmIzMx
         5/t9qLs0sVzcW+qQ59AwMKXpHgItXaSVY2wx+YjreWlzh82zMtFNDW28/byaFWlossT1
         elp3ETpoRHx89iOD2wW9YuMhrYVpomY7nrZF9qxXbyaUNtqH6yLMwNM1cAGQe38ezQdy
         V0Ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=DkZNJijr;
       spf=pass (google.com: domain of nahwanngaycra@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=nahwanngaycra@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id a14si452910wru.1.2019.09.08.12.27.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 08 Sep 2019 12:27:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of nahwanngaycra@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id p2so9892941edx.11
        for <kasan-dev@googlegroups.com>; Sun, 08 Sep 2019 12:27:36 -0700 (PDT)
X-Received: by 2002:a05:6402:b11:: with SMTP id bm17mr20769463edb.31.1567970856083;
        Sun, 08 Sep 2019 12:27:36 -0700 (PDT)
Received: from f6.my.com (f6.my.com. [185.30.176.74])
        by smtp.gmail.com with ESMTPSA id d2sm686646eda.20.2019.09.08.12.27.35
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 Sep 2019 12:27:35 -0700 (PDT)
From: nahwanngaycra@gmail.com
To: kuhwannihaela04@gmail.com
Cc: =?UTF-8?B?a2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
MIME-Version: 1.0
X-Mailer: My.com Mailer 1.0
Date: Sun, 08 Sep 2019 22:27:34 +0300
X-Letter-Fingerprint: ttScFsWweYg44XutIhHYmVGxCD5By8wd
Reply-To: nahwanngaycra@gmail.com
X-Priority: 3 (Normal)
Message-ID: <1567970854.895625857@f6.my.com>
Content-Type: multipart/alternative;
	boundary="--ALT--yhJzHbLcKqs8iPlqAkqYHi37NhhSAjoc1567970854"
X-77F55803: A0EE7B112D189DF9A0F21CC061F2095323D2FBEB2644075CD923C8D8DD37C99057433F358474A4B9B946989A47E9C19BA42E5ED7043A501F
X-7FA49CB5: 0D63561A33F958A56AAB8EEAE42912B0DF703E6F29783B37D97B18B10CB1E4328941B15DA834481FA18204E546F3947C1D471462564A2E19F6B57BC7E64490618DEB871D839B7333395957E7521B51C2545D4CF71C94A83E9FA2833FD35BB23D27C277FBC8AE2E8B2EE5AD8F952D28FBA471835C12D1D977C4224003CC83647689D4C264860C145E
X-DMARC-Policy: none
X-Mailru-MI: 800
X-Mailru-Sender: 5062038AA4CD0F5A5C934BAB97AA7373357135999712201EE72CCBBEA2C1F335EAC0E58D7C6C17765ADB52837C3B5A3C2236D74EC9BC5AD0D15821E16666CB4522DF1A08BD40178C22B820C1B2086D890DA7A0AF5A3A8387
X-Mras: OK
X-Spam: undefined
X-Original-Sender: nahwanngaycra@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=DkZNJijr;       spf=pass
 (google.com: domain of nahwanngaycra@gmail.com designates 2a00:1450:4864:20::535
 as permitted sender) smtp.mailfrom=nahwanngaycra@gmail.com;       dmarc=pass
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


----ALT--yhJzHbLcKqs8iPlqAkqYHi37NhhSAjoc1567970854
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable


--
=E0=B8=AA=E0=B9=88=E0=B8=87=E0=B8=88=E0=B8=B2=E0=B8=81 myMail =E0=B8=AA=E0=
=B8=B3=E0=B8=AB=E0=B8=A3=E0=B8=B1=E0=B8=9A Android

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1567970854.895625857%40f6.my.com.

----ALT--yhJzHbLcKqs8iPlqAkqYHi37NhhSAjoc1567970854
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable


<HTML><BODY><p style=3D"margin-top: 0px;" dir=3D"ltr"></p>=20
<div id=3D"mail-app-auto-default-signature">
 <p dir=3D"ltr">--<br> =E0=B8=AA=E0=B9=88=E0=B8=87=E0=B8=88=E0=B8=B2=E0=B8=
=81 myMail =E0=B8=AA=E0=B8=B3=E0=B8=AB=E0=B8=A3=E0=B8=B1=E0=B8=9A Android</=
p>
</div></BODY></HTML>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/1567970854.895625857%40f6.my.com?utm_medium=3Demail&ut=
m_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/1567970854.8=
95625857%40f6.my.com</a>.<br />

----ALT--yhJzHbLcKqs8iPlqAkqYHi37NhhSAjoc1567970854--
