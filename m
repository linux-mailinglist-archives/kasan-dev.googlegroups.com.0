Return-Path: <kasan-dev+bncBDBPDNNLZADBB3U24CYAMGQET4GXRQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D41EF8A19BD
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 18:18:56 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-516e914a04asf14854e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 09:18:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712852336; cv=pass;
        d=google.com; s=arc-20160816;
        b=eRjcqjiGxQwvktqxISY+BufIHF0lPYmZC3H4dj0QgTDD82l7UPejm/y//pzRzGhfM6
         xZ2T5lStfk+IHOw3e6fgVWhLfqAYdKnnLg7ehhudtdK0Nib1hW9P6LnPM9B7IhOnNTAK
         P6zfOXhSZVROOgRDWBOFGf0WGFKGxYoJ5R2zqRuA53tclQwMbSttSwjBMFBjXgKpOSW2
         vDymgyuJSeibaMW6RSrmTM3fE7oXbzoYRuymXAAyKkkmf/ehbYm+cjyycSHLbX05l524
         VA4wmb51WfiVvx+h772rIzogXuzj43Qbl+zeBgeC1OT2v3TLcIcpIivS/L2QoRHHTKK9
         IgoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=7SzluIk47XW+0sDv5+DZQeUPxbbhlfsqEyRAodT5Z78=;
        fh=/QvcJEAg39H5fEbIYvpPb0u18QQha6LJ1p21+fROXkM=;
        b=A33MbIMlAMqe/zD3mh0gdIOJ7o4svKv/j5dP13/6k8R96JHeZfO0+w1sDQRwya5sxq
         S/ei5+MH/6CoHrGCfxXahNruy3b2i2j2wIp0dW6X+uLqn98B4mRKlnGXoEmAx61XhxRj
         jPzirnhEVHmqVm0d8NRIQTef/hm+h4/dfKgG0UeXd+iwX5ntxRjSpx762tHr1BD6JSj8
         mVSroDlHWOdk5ERbkeWxzHvYoOrX+rCt6BeoODcrxFOSbzB0ZG6p+/pkOTsLN1mjY2gz
         h5LRtlBvGH2ovsNCgaq1jGpnOmrdEcC2Xbqex2r+LC3+fuCxnl9u3iIDI1/qIvZR+stw
         eypw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WD3PSszb;
       spf=pass (google.com: domain of krmorab@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=krmorab@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712852336; x=1713457136; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7SzluIk47XW+0sDv5+DZQeUPxbbhlfsqEyRAodT5Z78=;
        b=eV0Png/rSGbKHu6mVkvv3tzD1awUTu1fzzzhsTCXHVigFWalI7vIeFc0cVn3swMKtT
         onu6EOQfSxe78hK0kPVQJwbjA9VoKr8zF+CMcfEEm+zYOleJNh/GkaGcABEDnJbrSvwl
         EQsKi5DLd9iTEjj2/kMfn+tonG4LaipEgW/qgb1rqedikh3sAGERsbwwDlZKs0S5q+5V
         UTDlkXOjdTw3+xVYJAdWCymoPZmkxfFkGSAxdKAgr070u4+P72YjjKPMWiO01tJ3urwU
         CXaIk5vw/b3MYv4s0aaCuyL3vFSNVjpj17kdlGw4yqf/EDt+MYbEGv/qhpXv90tx4vAV
         QANQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1712852336; x=1713457136; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=7SzluIk47XW+0sDv5+DZQeUPxbbhlfsqEyRAodT5Z78=;
        b=Rh8nw26iZ8Kadhsq7iCqG7KKDup9CkKACXz2om5BobUgZSVMfm+B0b0Ba+VMZ8/T9/
         EJIeosdQPdLkSeqOizaxRh4FU5LGLkz0CVqCxWUVkfGDVbqUA/22cVXPgZ7SbVnMer4Y
         vccNo4+vMX9iRNIfZXITwQJP+5GkpwwEl4SeKSzdGuvKjNpU71p/ogHfipGDo2zYXDCg
         FA6Sln875/czX7iwtyimM80UGxuQtKFEdtyzshyaLHXiZy0IVfQhzZJ8PQUS5DXQ1w/V
         vp6ijOGHlIvCN+TvnuNkcBd2S20Sv0zFzY5HIE7VzejisWk4d9IhCriYlX0KP00VfHVk
         ttFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712852336; x=1713457136;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7SzluIk47XW+0sDv5+DZQeUPxbbhlfsqEyRAodT5Z78=;
        b=H3YkoEcyCaYP5Sgf7kwc3cV33akH2Ga1ewkjKWYIVvsrnckejAe0HMywsqLukFCTDM
         g/oXIysbjHePScU49T3Bhr+qtmaolu/5vV8s71AnJpva6POMbE2Q+LuG/K+4LX9ryOV1
         EAdU8tWRYK1g9WtoGcH8KsCNwq+dva+kLYTNH5gcEsDIHiQN1uSAUxFzoIDj5EpGuh6X
         d3cRh161ooNYLh1SZqw98B74H7us2NqPsXUDg7ojBqe66x8HQlEzFbFGpU0de1vl139U
         d8vUkmIwiIXV2pfvWO8CBR4GNWgS6t8cK6kyIDo7lsXcwJLmXnsk+rL2M2qI3HCoz2AG
         5Jjw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV+I4K6AI5kKf3o9cpF2PnhVTLq+jSi8Y3YRXz+uObc8aliUng/KdDkWLaCxkwR5NZoVHunDw7JgjLm7tjMqhQCZz4QWZvFNA==
X-Gm-Message-State: AOJu0YyPBpFR12y6hAqOJpPwsLKzi5odns1C+V05OiThWG2RAx3OnUJY
	bGAvtP1X1Ztvs4xE78IkEDYiE0ozgXZ+YijAPh6sTKBqu4BifvkN
X-Google-Smtp-Source: AGHT+IEnUOuKnKLEoFy+Tu+ORQulMPetN4M0A15e9Eh1qrVsNvm4iACngR9FnwCo7EI2NSUWU2ac9A==
X-Received: by 2002:ac2:5f52:0:b0:516:d099:400a with SMTP id 18-20020ac25f52000000b00516d099400amr148135lfz.0.1712852335128;
        Thu, 11 Apr 2024 09:18:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a60a:0:b0:2d8:2372:1471 with SMTP id v10-20020a2ea60a000000b002d823721471ls67375ljp.0.-pod-prod-08-eu;
 Thu, 11 Apr 2024 09:18:53 -0700 (PDT)
X-Received: by 2002:a2e:b54b:0:b0:2d8:9deb:c419 with SMTP id a11-20020a2eb54b000000b002d89debc419mr92755ljn.21.1712852332651;
        Thu, 11 Apr 2024 09:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712852332; cv=none;
        d=google.com; s=arc-20160816;
        b=Yfp0u1+Ujn2lz5Ozff2mQJEUUz601JJob9q7L0XthMYrIShPfNQ645qi5/bicSuJKe
         1LrhbWJ+IWimfsleu5hP60CQXwsS6lx0xWksADdkHOLthB84krVk8aOZhYEJpLfwxR6U
         xHerinjSyAdgRkSIrmxr9Ha8ZR/xSEOvaM2kfvoYuKZth8Gy4E0M7F7ZORq4bLQhcvx+
         VwZ3eWBzfCdu7OQqm6z7rIzrWyB4Qmm7aT9DQKGBO/idG+P9w0gQ54rvsANgP0de18NS
         SA/AdcJkKMado4/DDl0f7sgUO155tpUkMAlYituWJEPHpah4xzjloRfMJti2Ko24Ol19
         JO4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=jtU27OMgOCIQot8R7cNk93UZFWIyYhuRZcikaAVRMfg=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=jy0/pQINKSyNEyTlhedqvQuqu7CLxq0L3153OK1XuQadDXifSoaTsKKM9m8BZaRWT0
         EaMcjtwVVPxqD2b4bYIeNMIAQCrH72tDXCBLh/V1i7r8A/8b9Xun6Nu9ULG57BGuT2HV
         KYIkQhLnhO1B52nLjVdJWKjO36ADcSgqy22cDCmjp7nu/Bm7HZTkYpqvbnouohRYUuxe
         X7SUCVFqDbLLTkG+4Xeq+IjDUq+xVzU/9wlAdNWdl3v15+zHNfcdSvhyRjc9yTkZw16V
         2jhgQJdE7tUrAcuyjLhygNn3RhgsLs3h6Ve00tfRe+ItTWgRXCLuKyob/YGy0wm7ym5w
         DKtw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WD3PSszb;
       spf=pass (google.com: domain of krmorab@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=krmorab@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id u3-20020a2e91c3000000b002d9f81840eesi15115ljg.7.2024.04.11.09.18.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Apr 2024 09:18:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of krmorab@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id a640c23a62f3a-a52223e004dso91449966b.2
        for <kasan-dev@googlegroups.com>; Thu, 11 Apr 2024 09:18:52 -0700 (PDT)
X-Received: by 2002:a17:907:3e10:b0:a47:4bd6:9857 with SMTP id
 hp16-20020a1709073e1000b00a474bd69857mr143037ejc.64.1712852331402; Thu, 11
 Apr 2024 09:18:51 -0700 (PDT)
MIME-Version: 1.0
From: Krystal Hawley <lecaretzii21@gmail.com>
Date: Thu, 11 Apr 2024 16:18:39 +0000
Message-ID: <CAHjomh-xMHX=M_s6es_LH5HNj=ce2ftdc8T9v5wAo-c8rdpbSw@mail.gmail.com>
Subject: per favore fatemi sapere se avete ricevuto il mio messaggio precedente
To: kasan-dev@googlegroups.com
Content-Type: multipart/alternative; boundary="000000000000c41f440615d4825f"
X-Original-Sender: lecaretzii21@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WD3PSszb;       spf=pass
 (google.com: domain of krmorab@gmail.com designates 2a00:1450:4864:20::62b as
 permitted sender) smtp.mailfrom=krmorab@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000c41f440615d4825f
Content-Type: text/plain; charset="UTF-8"



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHjomh-xMHX%3DM_s6es_LH5HNj%3Dce2ftdc8T9v5wAo-c8rdpbSw%40mail.gmail.com.

--000000000000c41f440615d4825f
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAHjomh-xMHX%3DM_s6es_LH5HNj%3Dce2ftdc8T9v5wAo-c8rdpbS=
w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAHjomh-xMHX%3DM_s6es_LH5HNj%3Dce2ftdc8T9v5wAo-=
c8rdpbSw%40mail.gmail.com</a>.<br />

--000000000000c41f440615d4825f--
