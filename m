Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBDOJU7CQMGQEW3YUMHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 99C86B329EF
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Aug 2025 17:55:59 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-55ce508d927sf1832037e87.0
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Aug 2025 08:55:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755964559; cv=pass;
        d=google.com; s=arc-20240605;
        b=ULQshHAy7miJ79FLuZPxWaIdF1SfBKCcWALHBW6C205On7n1G2nqmSMRae7uMzTask
         QjZM2cBuE2JKhJQeJO4S1lwPcSA+CezFiV3hozuZ7JUKVMgJ30REtKBJPbnCUlUvcg3Y
         MtknJ06Axs4mxixPBv2/tLZ89MsmatB50ktVVeQeVh4XPVb5LlswE2/IOJ1IXsRQcNJv
         Asb4AJc9nzPyvnkDuXNwTW2xPeUdFPyMxvpQV+631NQ+1rwSigC92B7uliW6ENW1/BgY
         dy71exwVth7Z0QkXx9nh047xg5HjA/LCmJfTRvbhvoMfxCBtjhQmMJqL9jzJmPRoyj+r
         bHbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=BITcVGxny6/+I0bQv68pxNW+DDBCWBsBUfZqnu4qMQs=;
        fh=Z8f6Dz8JbhG+40zD7lKN6NbSvTXz4Foywb1R2TqvxZI=;
        b=AYdk+fTsBOea+/rH98vs5IZ5I1CqYkDMC3uf3G8KejH0/fVT92IceP3pDhO6cW4rir
         IsREHsQhQwi7JMPhjO/cg6dBGwPZqghfUQozcyvAI1npn23YOh4POSGq/Ivy1CPYpWrL
         keVoY7Kv/r8WET3XJnNwUcL1aSddjQi7dO7Ydvs936mAQd87sceKCkph4b2zRaskhwaC
         U3ODmdWNcpPduKwCmMa1MlZ2SvTIz2hyI3jI7JNvoLBUHmS32mO4KGnGrXpmor4yyUjH
         /DNhUcMiZsvvQVc1lfyQxEKSvUEw88KRTdBOrZU+qhJuKShsijDb7XY/J95HGe6QkWDP
         CYRA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mCReBl12;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755964559; x=1756569359; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BITcVGxny6/+I0bQv68pxNW+DDBCWBsBUfZqnu4qMQs=;
        b=JJ2ISUtiatUbPJnTX/iiKTocYsTQ8C+lQS/kw2ywdfW/KJC8p9PzyUmQUbCv3xvdJj
         +kauk9K8RXc1XD7D4EHuCziUesEgyibyZ/wlS3JuRaAN6hdMTNJ6XArkWfvrc9GYs2Fu
         YTpB4TlIKXsWJcrcjBwSy00EwUpTeQo+S51njbrRC93oWJZ7bo6jaVMeoPPv0oBPX9rv
         cPn1NzkzsQpz4lRTP1DpZFhnBQz/K3EovIAdK61ruolZ4bMrHU++SC5R2fOiaIP7DQVh
         aDtOuQkKZVF2b9xkImAyjyyOwDPWyW0FyXVxSAdSKiPLIm+t2DLrU9LOVea06eXVpgTD
         nhUw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755964559; x=1756569359; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=BITcVGxny6/+I0bQv68pxNW+DDBCWBsBUfZqnu4qMQs=;
        b=TwhZP8IrcKD7OLAypXRPf34+65+ZlpMjO5KOtF71VpmC1ZdSwUX3oMa6cNE7CcOyty
         jmsfMwyGbazbxcuIoLLwM0/5t9h4SgApFcNuxUtI9zLDMTCR6lp/C3sGtpTo/77BZ62B
         UtUm2nlUPNDYdjH5edxX25lXRFAgIFPbkYf/u7/AUTMRqGy6pSl2p8leE9Ct4iC/45kK
         knJX/NTwAckhh0QV7Ss09edCqP6TmqblRU6PWPcCz+mkDtp/QOfo9/lSsfLxWYhaw2z8
         +/4lI8/jU72XTMMr7PhichQk3jRwinE9+p+GnXbUwoB9//eMKLlJllM56GvVVerKwFio
         wqGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755964559; x=1756569359;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BITcVGxny6/+I0bQv68pxNW+DDBCWBsBUfZqnu4qMQs=;
        b=kTmMquIPA0ihJWBFwMVoUrAQDxak5uMYe44t6nFElbwSWyqQ/SL7WtV5dBZf/6VXlA
         LRwexS8JdYuoHkNDKhWqgATBnW5gzv6ahkHAyC4eghasI5ET7GVtzCD2AhJLIDjss+Se
         5XvM1Wf84IpXoLmkVFzIareTm1KFtzI0I9bwGffe2QXPZsSYhi8zpuWrQfeWCCx7nvtv
         auO9DooIvNeMcPXVp5CwCGCE7qmpR8qvW/WYE5/ryxk/xTnHdjwiFHMdPtD3dzjH2pT6
         t+6ryADCJt7BhB68T7+sLOKyks1EyNexDpbScUgvnC5hr3U1zTVkHb6gisA/7qmObmJs
         4RbQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmy0jAzthI/HDogGIGtLYESm+d3tAWuik449r63JLKNRFqz//JGaU07eaAOO6BF3qnIdNUsw==@lfdr.de
X-Gm-Message-State: AOJu0YwxFvvm0nj5hlW1WlIqWSoGo1QKYMZUyV0FXKus/gZrSRFJu9CF
	1gZqWiO19kKmy0wDEApBN435RFbr5hwSjLm/JbPGPuQxBo94eWeodbaZ
X-Google-Smtp-Source: AGHT+IEBlEb1G+3GAz0TYyFuaE+4st+VP0TJlQ7cwveYbZSYqBd2+4/mTP0EheLILHznha+UQ1MItQ==
X-Received: by 2002:a2e:a883:0:b0:333:bf9e:d6e1 with SMTP id 38308e7fff4ca-33651003282mr20737131fa.32.1755964558339;
        Sat, 23 Aug 2025 08:55:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfFkfWwBb4gvuL9yeoerwd67y4hR2OFk0uzwqc6npamag==
Received: by 2002:a05:651c:400e:b0:336:50ea:5a67 with SMTP id
 38308e7fff4ca-33650ea5b8fls2198311fa.0.-pod-prod-06-eu; Sat, 23 Aug 2025
 08:55:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmgatvwtdL1/XeB0b2TEd6MN9scZUcepreOM+trh7/4qoAZMOuhLJB5JYY5g2sZXwZOogxxcnXy4U=@googlegroups.com
X-Received: by 2002:ac2:5693:0:b0:55f:3faa:7bf5 with SMTP id 2adb3069b0e04-55f3faa828amr111261e87.41.1755964554529;
        Sat, 23 Aug 2025 08:55:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755964554; cv=none;
        d=google.com; s=arc-20240605;
        b=lxtFrMLLETM+xJCPhxvHMEuipJpYUdkts/+64xP7dY7GMqQBk33aoekL5c5lVen6FI
         QJjiUVuR1PR0/9Yw/Kj3frd7djYHizZpZaJANbLTU9v58kMdYWiQVicTcSuYRIiycbu3
         VtmxGHkUoiZFgxqfqKJxt+c8dwxkNRi0R1IEk4MAqVJB5qgE2KKbwa35c/YM7b3K4sAI
         OYXwU8XLbVYF/TM52k5pS2CpWiUjiaWivNZ9g0ZFmQzBO1REAdR9rREYrgafTCekQKpM
         tgGMQbEPSqGpfCpqudrzxlcuUoLhjEDaZ6pnLJVP6ToBWX7mv4kPnN1CdSdD0Qigp8hd
         Oo0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=rivHleLxjFGVzcbVapTjlvArMQyqFH+NPiMsXD+hac4=;
        fh=urzVvYOBD1eDSQmB4PHyyOJh2sl+P9pAHfmxQll5JRE=;
        b=UgucalufmgVnLzM0hS/0lNhKz3qJzo4sVB6uynrJ1JdzPhuhYU5Nr1QpImpL3P7jI3
         Hwk7K9R4zmTAaBLAIYKbJFKQ0EfYRD1KvC9c+06TiLjZC7zTfC4D9v3hy679RoO9O/wV
         W9rxh325/pOtNZlkOyFEPrj7BD5xuvp79cnZIXhTyI+vQfy1r/0w3rljLMCJ3A0Nim6t
         7gVXmE/Ye8+B+EfjHr5B8/MJS3Bfzm21Ma8ASVSuZ8kE8F9o2jVQxTDpD9za08Zn8sIv
         mpM153jGMo0AAlfSex+m79jDKWj3sp4kQHY3UZBJlk0DfAdOQ9t0hNZQag9GqX05Tb8E
         0UlQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mCReBl12;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55f35c65ba5si57612e87.4.2025.08.23.08.55.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 23 Aug 2025 08:55:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id 4fb4d7f45d1cf-618adc251f0so5276306a12.3
        for <kasan-dev@googlegroups.com>; Sat, 23 Aug 2025 08:55:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWCjxGgZFIBD1b8QDDHsQsAYYkdd2IYS9gcVy/x9hP3PscWW82t/ZUu/QF/gT5qGvhX+f9HvJLMU5A=@googlegroups.com
X-Gm-Gg: ASbGncsUabX8b4tAelGg8kHLRH9ePc1bhlWHEVD/8lFMM9ibVXCfDC3IOecV7LsBL3I
	MWiI4Sw6GDFRwOe8/09Qy4P3bxGlr9bQIRvH1GOA3Fhhv5TEAjTacAyP5su8Fw6zs9JYCFhbWn7
	9Z507iYqLYtNug8AWAsKZB8KaPFab75oCliLAe9xScI3fG/I/a6QRD2mxLkTc8yihotmrTGUJAX
	EGk0LXdik/GALPcLdmGKRs=
X-Received: by 2002:a05:6402:278c:b0:61a:7393:3806 with SMTP id
 4fb4d7f45d1cf-61c1b923f1emr5190837a12.38.1755964553369; Sat, 23 Aug 2025
 08:55:53 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Sat, 23 Aug 2025 18:55:41 +0300
X-Gm-Features: Ac12FXwZCJMuOestcWoFFIZ3PnFhfhLSrjctxr49hutYUoroP3tilW09dEc3pXI
Message-ID: <CADj1ZK=wZ2j4H0fwLDQyj0=32CAEA4K6r=208=_4bDxDpMokUw@mail.gmail.com>
Subject: =?UTF-8?B?8J+TnCDYo9mF2YrZhiDYs9ixINmF2KzZhNizINin2YTYpdiv2KfYsdipINin2YTZhdit?=
	=?UTF-8?B?2KrYsdmBIFByb2Zlc3Npb25hbCBCb2FyZCBTZWNyZXRhcnkg2KfZhNiq2KfYsdmK2K46INmF2YYgMzEg?=
	=?UTF-8?B?2KPYutiz2LfYsyDYpdmE2YkgNCDYs9io2KrZhdio2LEgMjAyNSDYp9mE2YXZg9in2YY6INin2YTZgtin?=
	=?UTF-8?B?2YfYsdipIOKAkyDYrNmF2YfZiNix2YrYqSDZhdi12LEg2KfZhNi52LHYqNmK2Kkg2KPZiCDYudio2LEg?=
	=?UTF-8?B?2KfZhNil2YbYqtix2YbYqiAoWm9vbSkg2YHZiiDYrdin2YQg2KrYudiw2LEg2KfZhNit2LbZiNixINmF?=
	=?UTF-8?B?2YLYr9mF2Kkg2YXZhjog2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE?=
	=?UTF-8?B?2KXYr9in2LHZitipIOKAkyBBSEFEINi02YfYp9iv2Kkg2KfYrNiq2YrYp9iyINmF2LnYqtmF2K/YqSA=?=
	=?UTF-8?B?2YjZhdmI2KvZgtipINmC2KfYqNmE2Kkg2YTZhNiq2LXYr9mK2YIg2YXZhiDYp9mE2K7Yp9ix2KzZitip?=
	=?UTF-8?B?INmI2YPYp9mB2Kkg2KfZhNiz2YHYp9ix2KfYqiDYp9mE2LnYsdio2YrYqSDYp9mE2YXZgtiv2YXYqSA=?=
	=?UTF-8?B?2KrYudivINmI2LjZitmB2Kkg2KPZhdmK2YYg2LPYsSDZhdis2YTYsyDYp9mE2KXYr9in2LHYqSDZhdmG?=
	=?UTF-8?B?INij2YfZhSDYp9mE2YXZhtin2LXYqCDYp9mE2KrZiiDYqtiz2KfZh9mFINmB2Yog2LbZhdin2YYg2K0=?=
	=?UTF-8?B?2YjZg9mF2Kkg2KfZhNi02LHZg9in2Kog2KjYtNmD2YQg2YHYudmR2KfZhNiMINit2YrYqyDZitmP2Lk=?=
	=?UTF-8?B?2KrYqNixINmH2YXYstipINin2YTZiNi12YQg2KjZitmGINij2LnYttin2KEg2KfZhNmF2KzZhNizINmI?=
	=?UTF-8?B?2KfZhNil2K/Yp9ix2Kkg2KfZhNiq2YbZgdmK2LDZitip2Iwg2YjZhdiz2KTZiNmE2YvYpyDYudmGINiq?=
	=?UTF-8?B?2YbYuNmK2YUg2KfZhNin2KzYqtmF2KfYudin2Kog2YjYqtmI2KvZitmCINin2YTZgtix2KfYsdin2Kog?=
	=?UTF-8?B?2YjYqti32KjZitmCINin2YTZhNmI2KfYptitINin2YTYr9in2K7ZhNmK2Kkg2YjYp9mE2K7Yp9ix2Kw=?=
	=?UTF-8?B?2YrYqS4g2KfZhNij2YfYr9in2YEg4oCiINiq2YXZg9mK2YYg2KfZhNmF2LTYp9ix2YM=?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000711f5f063d0a5bb9"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mCReBl12;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52d
 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;       dmarc=pass
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

--000000000000711f5f063d0a5bb9
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

8J+TnCog2KPZhdmK2YYg2LPYsSDZhdis2YTYsyDYp9mE2KXYr9in2LHYqSDYp9mE2YXYrdiq2LHZ
gSoNCg0KKlByb2Zlc3Npb25hbCBCb2FyZCBTZWNyZXRhcnkqDQoq2KfZhNiq2KfYsdmK2K4qKjoq
INmF2YYgMzEg2KPYutiz2LfYsyDYpdmE2YkgNCDYs9io2KrZhdio2LEgMjAyNQ0KKtin2YTZhdmD
2KfZhioqOiog2KfZhNmC2KfZh9ix2Kkg4oCTINis2YXZh9mI2LHZitipINmF2LXYsSDYp9mE2LnY
sdio2YrYqQ0KKtij2Ygg2LnYqNixINin2YTYpdmG2KrYsdmG2KoqKiAoWm9vbSkgKirZgdmKINit
2KfZhCDYqti52LDYsSDYp9mE2K3YttmI2LEqDQrZhdmC2K/ZhdipINmF2YY6ICrYp9mE2K/Yp9ix
INin2YTYudix2KjZitipINmE2YTYqtmG2YXZitipINin2YTYpdiv2KfYsdmK2KkqKiDigJMgQUhB
RCoNCirYtNmH2KfYr9ipINin2KzYqtmK2KfYsiDZhdi52KrZhdiv2Kkg2YjZhdmI2KvZgtipINmC
2KfYqNmE2Kkg2YTZhNiq2LXYr9mK2YIg2YXZhiDYp9mE2K7Yp9ix2KzZitipINmI2YPYp9mB2Kkg
2KfZhNiz2YHYp9ix2KfYqg0K2KfZhNi52LHYqNmK2KkqDQoNCg0KDQoq2KfZhNmF2YLYr9mF2Kkq
DQoNCtiq2LnYryDZiNi42YrZgdipINij2YXZitmGINiz2LEg2YXYrNmE2LMg2KfZhNil2K/Yp9ix
2Kkg2YXZhiDYo9mH2YUg2KfZhNmF2YbYp9i12Kgg2KfZhNiq2Yog2KrYs9in2YfZhSDZgdmKINi2
2YXYp9mGINit2YjZg9mF2KkNCtin2YTYtNix2YPYp9iqINio2LTZg9mEINmB2LnZkdin2YTYjCDY
rdmK2Ksg2YrZj9i52KrYqNixINmH2YXYstipINin2YTZiNi12YQg2KjZitmGINij2LnYttin2KEg
2KfZhNmF2KzZhNizINmI2KfZhNil2K/Yp9ix2KkNCtin2YTYqtmG2YHZitiw2YrYqdiMINmI2YXY
s9ik2YjZhNmL2Kcg2LnZhiDYqtmG2LjZitmFINin2YTYp9is2KrZhdin2LnYp9iqINmI2KrZiNir
2YrZgiDYp9mE2YLYsdin2LHYp9iqINmI2KrYt9io2YrZgiDYp9mE2YTZiNin2KbYrQ0K2KfZhNiv
2KfYrtmE2YrYqSDZiNin2YTYrtin2LHYrNmK2KkuDQoNCg0KDQoq2KfZhNij2YfYr9in2YEqDQoN
CiAgIC0g2KrZhdmD2YrZhiDYp9mE2YXYtNin2LHZg9mK2YYg2YXZhiDZgdmH2YUg2KfZhNiv2YjY
sSDYp9mE2KfYs9iq2LHYp9iq2YrYrNmKINmE2KPZhdmK2YYg2KfZhNiz2LEg2YHZiiDYp9mE2K3Z
iNmD2YXYqSDYp9mE2YXYpNiz2LPZitipDQogICAuDQogICAtINil2YPYs9in2KjZh9mFINin2YTZ
hdmH2KfYsdin2Kog2KfZhNi52YXZhNmK2Kkg2YHZiiDYpdi52K/Yp9ivINmI2KrYrdi22YrYsSDY
p9is2KrZhdin2LnYp9iqINin2YTZhdis2YTYsyDZiNiq2YjYq9mK2YLZh9inLg0KICAgLSDYqtiv
2LHZitio2YfZhSDYudmE2Ykg2KfZhNiq2LnYp9mF2YQg2YXYuSDYp9mE2YLZiNin2YbZitmGINmI
2KfZhNmE2YjYp9im2K0g2KfZhNmF2YbYuNmF2Kkg2YTYudmF2YQg2KfZhNi02LHZg9in2KouDQog
ICAtINiq2YbZhdmK2Kkg2YXZh9in2LHYp9iqINin2YTYp9iq2LXYp9mEINmI2KfZhNiq2YbYs9mK
2YIg2YXYuSDYo9i52LbYp9ihINin2YTZhdis2YTYsyDZiNin2YTYrNmH2KfYqiDYp9mE2LHZgtin
2KjZitipLg0KDQoNCg0KKtin2YTZgdim2Kkg2KfZhNmF2LPYqtmH2K/ZgdipKg0KDQogICAtINij
2YXZhtin2KEg2LPYsSDZhdis2KfZhNizINin2YTYpdiv2KfYsdipINin2YTYrdin2YTZitmI2YYg
2YjYp9mE2YXYs9iq2YLYqNmE2YrZiNmGLg0KICAgLSDYp9mE2YXYr9mK2LHZiNmGINin2YTYqtmG
2YHZitiw2YrZiNmGINmI2YXYr9mK2LHZiCDZhdmD2KfYqtioINin2YTYpdiv2KfYsdipINin2YTY
udmE2YrYpy4NCiAgIC0g2YXYs9ik2YjZhNmIINin2YTYrdmI2YPZhdipINmI2KfZhNin2YTYqtiy
2KfZhSDZiNin2YTYsdmC2KfYqNipINin2YTYr9in2K7ZhNmK2KkuDQoNCg0KDQoq2KfZhNmF2K3Y
p9mI2LEg2KfZhNiq2K/YsdmK2KjZitipKg0KDQoq2KfZhNmK2YjZhSDYp9mE2KPZiNmEKio6Kg0K
DQogICAtINmF2YHZh9mI2YUg2KfZhNit2YjZg9mF2Kkg2YjYo9mH2YXZitipINiv2YjYsSDYo9mF
2YrZhiDYs9ixINin2YTZhdis2YTYsy4NCiAgIC0g2KfZhNil2LfYp9ixINin2YTZgtin2YbZiNmG
2Yog2YjYp9mE2KrZhti42YrZhdmKINmE2LnZhdmEINin2YTZhdis2KfZhNizLg0KDQoq2KfZhNmK
2YjZhSDYp9mE2KvYp9mG2YoqKjoqDQoNCiAgIC0g2KrZhti42YrZhSDYp9is2KrZhdin2LnYp9iq
INin2YTZhdis2YTYsyAo2YLYqNmEIOKAkyDYo9ir2YbYp9ihIOKAkyDYqNi52K8pLg0KICAgLSDY
pdi52K/Yp9ivINis2K/Yp9mI2YQg2KfZhNij2LnZhdin2YQg2YjZhdiw2YPYsdin2Kog2KfZhNin
2KzYqtmF2KfYuS4NCg0KKtin2YTZitmI2YUg2KfZhNir2KfZhNirKio6Kg0KDQogICAtINmD2KrY
p9io2Kkg2YXYrdin2LbYsSDYp9mE2KfYrNiq2YXYp9i52KfYqiDYqNin2K3Yqtix2KfZgdmK2Kku
DQogICAtINil2K/Yp9ix2Kkg2KfZhNmF2LHYp9iz2YTYp9iqINin2YTYsdiz2YXZitipINmI2KfZ
hNiq2YLYp9ix2YrYsSDYp9mE2LPZhtmI2YrYqS4NCg0KKtin2YTZitmI2YUg2KfZhNix2KfYqNi5
Kio6Kg0KDQogICAtINin2YTYqti52KfZhdmEINmF2Lkg2KPYudi22KfYoSDYp9mE2YXYrNmE2LMg
2YjYp9mE2YXYs9iq2KvZhdix2YrZhi4NCiAgIC0g2LbZhdin2YYg2KfZhNin2YXYqtir2KfZhCDZ
hNmE2LPZitin2LPYp9iqINin2YTYr9in2K7ZhNmK2Kkg2YjYp9mE2K7Yp9ix2KzZitipLg0KDQoq
2KfZhNmK2YjZhSDYp9mE2K7Yp9mF2LMqKjoqDQoNCiAgIC0g2KfYs9iq2K7Yr9in2YUg2KfZhNiq
2YPZhtmI2YTZiNis2YrYpyDZgdmKINil2K/Yp9ix2Kkg2KfZhNin2KzYqtmF2KfYudin2KouDQog
ICAtINmG2YXYp9iw2Kwg2YjYqti32KjZitmC2KfYqiDYudmF2YTZitipINmI2YXYrdin2YPYp9ip
INis2YTYs9in2Kog2YXYrNmE2LMg2KfZhNil2K/Yp9ix2KkuDQoNCirZhNmE2KrYs9is2YrZhCDZ
iNin2YTYp9iz2KrZgdiz2KfYsSoNCg0KKtmI2KjZh9iw2Ycg2KfZhNmF2YbYp9iz2KjYqSDZitiz
2LnYr9mG2Kcg2K/YudmI2KrZg9mFINmE2YTZhdi02KfYsdmD2Kkg2YjYqti52YXZitmFINiu2LfY
p9io2YbYpyDYudmE2Ykg2KfZhNmF2YfYqtmF2YrZhg0K2KjZhdmA2YDZiNi22YDZiNi5ICoq2KfZ
hNi02YfYp9iv2Kkg2KfZhNin2K3Yqtix2KfZgdmK2KkgKirZiNil2YHYp9iv2KrZhtinINio2YXZ
hiDYqtmC2KrYsdit2YjZhiDYqtmI2KzZitmHINin2YTYr9i52YjYqSDZhNmH2YUqDQoNCirZhNmF
2LLZitivINmF2YYg2KfZhNmF2LnZhNmI2YXYp9iqINmK2YXZg9mG2YMg2KfZhNiq2YjYp9i12YQg
2YXYuSDYoyAvINiz2KfYsdipINi52KjYryDYp9mE2KzZiNin2K8g4oCTINmG2KfYptioINmF2K/Z
itixDQrYp9mE2KrYr9ix2YrYqCDigJMg2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZ
htmF2YrYqSDYp9mE2KfYr9in2LHZitipKg0KDQoq2KzZiNin2YQg4oCTINmI2KfYqtizINin2Kgg
OioNCg0KKjAwMjAxMDY5OTk0Mzk5IC0wMDIwMTA2Mjk5MjUxMCAtIDAwMjAxMDk2ODQxNjI2Kg0K
DQoNCirYp9mE2K/ZiNix2KfYqiDYp9mE2YXYqtmC2K/ZhdipINmB2Yog2KfZhNit2YjZg9mF2Kkg
2KfZhNmF2KTYs9iz2YrYqSDZhNmE2YHYqtix2Kkg2YXZhiAzMSDYp9i62LPYt9izINin2YTZiSA0
INiz2KjYqtmF2KjYsSAyMDI1Kg0KDQoq2YUqDQoNCirYp9iz2YUg2KfZhNio2LHZhtin2YXYrCDY
p9mE2KrYr9ix2YrYqNmKKg0KDQoq2KfZhNmF2K3Yp9mI2LEg2KfZhNix2KbZitiz2YrYqSoNCg0K
MQ0KDQoq2KfZhNi02YfYp9iv2Kkg2KfZhNmF2KrZgtiv2YXYqSDZgdmKINin2YTYrdmI2YPZhdip
INin2YTZhdik2LPYs9mK2Kkg2YjYo9mB2LbZhCDYp9mE2YXZhdin2LHYs9in2KoqDQoNCi0g2YXY
qNin2K/YpiDYp9mE2K3ZiNmD2YXYqSDYp9mE2LHYtNmK2K/YqQ0KLSDYp9mE2KPYt9ixINin2YTY
r9mI2YTZitipINmE2YTYrdmI2YPZhdipDQotINin2YTYtNmB2KfZgdmK2Kkg2YjYp9mE2YXYs9in
2KHZhNipDQotINin2YTYudmE2KfZgtipINio2YrZhiDZhdis2YTYsyDYp9mE2KXYr9in2LHYqSDZ
iNin2YTZhdiu2KfYt9ixDQoNCjINCg0KKtin2YTYp9iz2KrYsdin2KrZitis2YrYp9iqINin2YTZ
hdiq2YLYr9mF2Kkg2YHZiiDYp9mE2K3ZiNmD2YXYqSDYp9mE2YXYpNiz2LPZitipKg0KDQotINin
2YTYsdio2Lcg2KjZitmGINin2YTYrdmI2YPZhdipINmI2KfZhNil2K/Yp9ix2Kkg2KfZhNin2LPY
qtix2KfYqtmK2KzZitipDQotINin2YTYrdmI2YPZhdipINmI2KfZhNmF2K7Yp9i32LEg2YjYp9mE
2KfZhdiq2KvYp9mEIChHUkMpDQotINil2LfYp9ixINin2YTYrdmI2YPZhdipINin2YTZgdi52KfZ
hA0KDQozDQoNCirYrdmI2YPZhdipINin2YTYtNix2YPYp9iqINmI2KXYr9in2LHYqSDYp9mE2YXY
rtin2LfYsSDZiNin2YTYp9mF2KrYq9in2YQqDQoNCi0g2K3ZiNmD2YXYqSDYp9mE2LTYsdmD2KfY
qiDZiNij2K/ZiNin2LEg2KfZhNmF2KzYp9mE2LMNCi0g2KfZhNiq2K3Zg9mFINmB2Yog2KfZhNmF
2K7Yp9i32LEg2YjYp9mE2KfZhdiq2KvYp9mEDQotINiz2YrYp9iz2KfYqiDYp9mE2K3ZiNmD2YXY
qSDYp9mE2K/Yp9iu2YTZitipDQoNCjQNCg0KKtin2YTYrdmI2YPZhdipINmI2KfZhNin2KjYqtmD
2KfYsSDYp9mE2LHZgtmF2Yog2YTZhdis2KfZhNizINin2YTYpdiv2KfYsdipKg0KDQotINiv2YjY
sSDYp9mE2K3ZiNmD2YXYqSDZgdmKINin2YTYqtit2YjZhCDYp9mE2LHZgtmF2YoNCi0g2KrYt9io
2YrZgtin2Kog2KfZhNiw2YPYp9ihINin2YTYp9i12LfZhtin2LnZiiDZgdmKINin2YTYo9mF2KfZ
htipINin2YTYudin2YXYqSDZhNmE2YXYrNmE2LMNCi0g2KfZhNij2LfYsSDYp9mE2KrZhti42YrZ
hdmK2Kkg2YTZhNiw2YPYp9ihINin2YTYp9i12LfZhtin2LnZig0KDQo1DQoNCirYrdmI2YPZhdip
INin2YTYtNix2YPYp9iqINmB2Yog2KfZhNmC2LfYp9i5INin2YTZhdin2YTZiioNCg0KLSDYrdmI
2YPZhdipINin2YTZhdik2LPYs9in2Kog2KfZhNmF2KfZhNmK2KkNCi0g2KfZhNin2YXYqtir2KfZ
hCDZhNmE2YjYp9im2K0g2KfZhNio2YbZiNmDINin2YTZhdix2YPYstmK2KkNCi0g2KXYr9in2LHY
qSDYp9mE2YXYrtin2LfYsSDYp9mE2YXYpNiz2LPZitipDQoNCi0tIApZb3UgcmVjZWl2ZWQgdGhp
cyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBz
ICJrYXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0
b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIGthc2FuLWRldit1
bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiB2aXNp
dCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L0NBRGoxWkslM0R3
WjJqNEgwZndMRFF5ajAlM0QzMkNBRUE0SzZyJTNEMjA4JTNEXzRiRHhEcE1va1V3JTQwbWFpbC5n
bWFpbC5jb20uCg==
--000000000000711f5f063d0a5bb9
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;m=
argin:0in 0in 8pt;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;=
"><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Segoe UI Symb=
ol&quot;,&quot;sans-serif&quot;">=F0=9F=93=9C</span><span dir=3D"RTL"></spa=
n><span dir=3D"RTL"></span><b><span style=3D"font-size:18pt;font-family:&qu=
ot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"RTL"></span><span =
dir=3D"RTL"></span>
<span lang=3D"AR-SA">=D8=A3=D9=85=D9=8A=D9=86 =D8=B3=D8=B1 =D9=85=D8=AC=D9=
=84=D8=B3 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=
=AD=D8=AA=D8=B1=D9=81</span></span></b><b><span dir=3D"LTR" style=3D"font-s=
ize:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span>=
</b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">Professional Board Secretary</span></b><span dir=3D"LTR" style=
=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot=
;"><br>
</span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D8=AA=D8=A7=D8=B1=D9=8A=
=D8=AE</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span=
 dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot=
;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</s=
pan></b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times N=
ew Roman&quot;,&quot;serif&quot;"> </span><span lang=3D"AR-SA" style=3D"fon=
t-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D9=
=85=D9=86 31 =D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 =D8=A5=D9=84=D9=89 4 =D8=B3=D8=
=A8=D8=AA=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"LTR" style=3D"font-size=
:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><br>
</span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=85=D9=83=D8=A7=D9=86=
</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span>=
</b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New R=
oman&quot;,&quot;serif&quot;"> </span><span lang=3D"AR-SA" style=3D"font-si=
ze:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A7=
=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9 =E2=80=93 =D8=AC=D9=85=D9=87=D9=88=D8=
=B1=D9=8A=D8=A9 =D9=85=D8=B5=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=
=A9</span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times=
 New Roman&quot;,&quot;serif&quot;"><br>
</span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D8=A3=D9=88 =D8=B9=D8=A8=D8=B1 =D8=
=A7=D9=84=D8=A5=D9=86=D8=AA=D8=B1=D9=86=D8=AA</span></b><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:18pt=
;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span> (Zoom) </span></b><b><span lang=3D"AR-S=
A" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;se=
rif&quot;">=D9=81=D9=8A =D8=AD=D8=A7=D9=84 =D8=AA=D8=B9=D8=B0=D8=B1 =D8=A7=
=D9=84=D8=AD=D8=B6=D9=88=D8=B1</span></b><span dir=3D"LTR" style=3D"font-si=
ze:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><br>
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times=
 New Roman&quot;,&quot;serif&quot;">=D9=85=D9=82=D8=AF=D9=85=D8=A9 =D9=85=
=D9=86</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot=
;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:
</span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=
=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=
=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></b><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"f=
ont-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span> =E2=80=93 AHAD</span></b><=
span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&=
quot;,&quot;serif&quot;"><br>
</span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D8=
=A7=D8=AC=D8=AA=D9=8A=D8=A7=D8=B2 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9 =D9=
=88=D9=85=D9=88=D8=AB=D9=82=D8=A9 =D9=82=D8=A7=D8=A8=D9=84=D8=A9
=D9=84=D9=84=D8=AA=D8=B5=D8=AF=D9=8A=D9=82 =D9=85=D9=86 =D8=A7=D9=84=D8=AE=
=D8=A7=D8=B1=D8=AC=D9=8A=D8=A9 =D9=88=D9=83=D8=A7=D9=81=D8=A9 =D8=A7=D9=84=
=D8=B3=D9=81=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=
=D8=A9</span></b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quo=
t;Times New Roman&quot;,&quot;serif&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=85=D9=82=D8=AF=D9=85=D8=A9</span></b><b><sp=
an dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&qu=
ot;,&quot;serif&quot;"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=D8=AA=D8=B9=D8=AF =D9=88=D8=B8=D9=8A=D9=81=D8=A9 =D8=A3=D9=85=
=D9=8A=D9=86 =D8=B3=D8=B1 =D9=85=D8=AC=D9=84=D8=B3 =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D8=A9 =D9=85=D9=86
=D8=A3=D9=87=D9=85 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B5=D8=A8 =D8=A7=D9=84=
=D8=AA=D9=8A =D8=AA=D8=B3=D8=A7=D9=87=D9=85 =D9=81=D9=8A =D8=B6=D9=85=D8=A7=
=D9=86 =D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A7=
=D8=AA =D8=A8=D8=B4=D9=83=D9=84 =D9=81=D8=B9=D9=91=D8=A7=D9=84=D8=8C =D8=AD=
=D9=8A=D8=AB =D9=8A=D9=8F=D8=B9=D8=AA=D8=A8=D8=B1 =D9=87=D9=85=D8=B2=D8=A9 =
=D8=A7=D9=84=D9=88=D8=B5=D9=84
=D8=A8=D9=8A=D9=86 =D8=A3=D8=B9=D8=B6=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=AC=
=D9=84=D8=B3 =D9=88=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=
=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=8A=D8=A9=D8=8C =D9=88=D9=85=D8=B3=D8=A4=
=D9=88=D9=84=D9=8B=D8=A7 =D8=B9=D9=86 =D8=AA=D9=86=D8=B8=D9=8A=D9=85 =D8=A7=
=D9=84=D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D8=A7=D8=AA =D9=88=D8=AA=D9=88=
=D8=AB=D9=8A=D9=82
=D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1=D8=A7=D8=AA =D9=88=D8=AA=D8=B7=D8=A8=
=D9=8A=D9=82 =D8=A7=D9=84=D9=84=D9=88=D8=A7=D8=A6=D8=AD =D8=A7=D9=84=D8=AF=
=D8=A7=D8=AE=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AE=D8=A7=D8=B1=D8=AC=
=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;=
,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</sp=
an></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D8=A3=D9=87=D8=AF=D8=A7=D9=81</span></b><b><sp=
an dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&qu=
ot;,&quot;serif&quot;"></span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=AA=D9=85=D9=83=D9=8A=D9=86
     =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D9=85=D9=86 =
=D9=81=D9=87=D9=85 =D8=A7=D9=84=D8=AF=D9=88=D8=B1 =D8=A7=D9=84=D8=A7=D8=B3=
=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A =D9=84=D8=A3=D9=85=D9=8A=D9=86 =
=D8=A7=D9=84=D8=B3=D8=B1 =D9=81=D9=8A =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=
=D8=A9 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=D8=A9</span><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:1=
8pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A5=D9=83=D8=B3=D8=A7=D8=A8=D9=87=D9=85
     =D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D9=
=85=D9=84=D9=8A=D8=A9 =D9=81=D9=8A =D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D9=88=D8=
=AA=D8=AD=D8=B6=D9=8A=D8=B1 =D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D8=A7=D8=
=AA =D8=A7=D9=84=D9=85=D8=AC=D9=84=D8=B3 =D9=88=D8=AA=D9=88=D8=AB=D9=8A=D9=
=82=D9=87=D8=A7</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><sp=
an dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&qu=
ot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.<=
/span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=87=D9=85
     =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=85=
=D8=B9 =D8=A7=D9=84=D9=82=D9=88=D8=A7=D9=86=D9=8A=D9=86 =D9=88=D8=A7=D9=84=
=D9=84=D9=88=D8=A7=D8=A6=D8=AD =D8=A7=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A9 =
=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A7=D8=AA</span><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D=
"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=
<span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=AA=D9=86=D9=85=D9=8A=D8=A9
     =D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A7=D8=AA=D8=B5=D8=
=A7=D9=84 =D9=88=D8=A7=D9=84=D8=AA=D9=86=D8=B3=D9=8A=D9=82 =D9=85=D8=B9 =D8=
=A3=D8=B9=D8=B6=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=AC=D9=84=D8=B3 =D9=88=D8=
=A7=D9=84=D8=AC=D9=87=D8=A7=D8=AA =D8=A7=D9=84=D8=B1=D9=82=D8=A7=D8=A8=D9=
=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span>=
</li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=81=D8=A6=D8=A9
=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9</span></b><b><span d=
ir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,=
&quot;serif&quot;"></span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A3=D9=85=D9=86=D8=A7=D8=A1
     =D8=B3=D8=B1 =D9=85=D8=AC=D8=A7=D9=84=D8=B3 =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AD=D8=A7=D9=84=D9=8A=D9=88=D9=86 =D9=88=
=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=82=D8=A8=D9=84=D9=8A=D9=88=D9=86</span><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"=
font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D9=85=D8=AF=D9=8A=D8=B1=D9=88=D9=86
     =D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=8A=D9=88=D9=86 =D9=88=D9=
=85=D8=AF=D9=8A=D8=B1=D9=88 =D9=85=D9=83=D8=A7=D8=AA=D8=A8 =D8=A7=D9=84=D8=
=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B9=D9=84=D9=8A=D8=A7</span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"fo=
nt-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88
     =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=88=D8=A7=D9=84=D8=A7=D9=
=84=D8=AA=D8=B2=D8=A7=D9=85 =D9=88=D8=A7=D9=84=D8=B1=D9=82=D8=A7=D8=A8=D8=
=A9 =D8=A7=D9=84=D8=AF=D8=A7=D8=AE=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:18pt=
;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span>.</span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=88=D8=B1
=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9</span></b><b><span d=
ir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,=
&quot;serif&quot;"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=8A=D9=88=D9=85
=D8=A7=D9=84=D8=A3=D9=88=D9=84</span></b><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&q=
uot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span=
 dir=3D"LTR"></span>:</span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=85=D9=81=D9=87=D9=88=D9=85
     =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=88=D8=A3=D9=87=D9=85=D9=
=8A=D8=A9 =D8=AF=D9=88=D8=B1 =D8=A3=D9=85=D9=8A=D9=86 =D8=B3=D8=B1 =D8=A7=
=D9=84=D9=85=D8=AC=D9=84=D8=B3</span><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Tim=
es New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D=
"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D8=A5=D8=B7=D8=A7=D8=B1
     =D8=A7=D9=84=D9=82=D8=A7=D9=86=D9=88=D9=86=D9=8A =D9=88=D8=A7=D9=84=D8=
=AA=D9=86=D8=B8=D9=8A=D9=85=D9=8A =D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D9=
=85=D8=AC=D8=A7=D9=84=D8=B3</span><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times =
New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LT=
R"></span>.</span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=8A=D9=88=D9=85
=D8=A7=D9=84=D8=AB=D8=A7=D9=86=D9=8A</span></b><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:18pt;font-fam=
ily:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span>:</span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=AA=D9=86=D8=B8=D9=8A=D9=85
     =D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=
=AC=D9=84=D8=B3 (=D9=82=D8=A8=D9=84 =E2=80=93 =D8=A3=D8=AB=D9=86=D8=A7=D8=
=A1 =E2=80=93 =D8=A8=D8=B9=D8=AF)</span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot=
;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span di=
r=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
     =D8=AC=D8=AF=D8=A7=D9=88=D9=84 =D8=A7=D9=84=D8=A3=D8=B9=D9=85=D8=A7=D9=
=84 =D9=88=D9=85=D8=B0=D9=83=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A7=D8=AC=D8=
=AA=D9=85=D8=A7=D8=B9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Ro=
man&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan>.</span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=8A=D9=88=D9=85
=D8=A7=D9=84=D8=AB=D8=A7=D9=84=D8=AB</span></b><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:18pt;font-fam=
ily:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span>:</span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=83=D8=AA=D8=A7=D8=A8=D8=A9
     =D9=85=D8=AD=D8=A7=D8=B6=D8=B1 =D8=A7=D9=84=D8=A7=D8=AC=D8=AA=D9=85=D8=
=A7=D8=B9=D8=A7=D8=AA =D8=A8=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=
=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LT=
R" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;se=
rif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
     =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=B3=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=
=B1=D8=B3=D9=85=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D9=82=D8=A7=D8=B1=D9=
=8A=D8=B1 =D8=A7=D9=84=D8=B3=D9=86=D9=88=D9=8A=D8=A9</span><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:18pt=
;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span>.</span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=8A=D9=88=D9=85
=D8=A7=D9=84=D8=B1=D8=A7=D8=A8=D8=B9</span></b><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:18pt;font-fam=
ily:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span>:</span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84
     =D9=85=D8=B9 =D8=A3=D8=B9=D8=B6=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=AC=
=D9=84=D8=B3 =D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D8=AB=D9=85=D8=B1=D9=8A=
=D9=86</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot=
;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></l=
i>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=B6=D9=85=D8=A7=D9=86
     =D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=D8=A7=D9=84 =D9=84=D9=84=D8=B3=D9=
=8A=D8=A7=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D8=AF=D8=A7=D8=AE=D9=84=D9=8A=D8=
=A9 =D9=88=D8=A7=D9=84=D8=AE=D8=A7=D8=B1=D8=AC=D9=8A=D8=A9</span><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-si=
ze:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span di=
r=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=8A=D9=88=D9=85
=D8=A7=D9=84=D8=AE=D8=A7=D9=85=D8=B3</span></b><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:18pt;font-fam=
ily:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span>:</span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85
     =D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =D9=
=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A7=D8=AC=D8=AA=D9=
=85=D8=A7=D8=B9=D8=A7=D8=AA</span><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times =
New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LT=
R"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=86=D9=85=D8=A7=D8=B0=D8=AC
     =D9=88=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA =D8=B9=D9=85=D9=84=D9=
=8A=D8=A9 =D9=88=D9=85=D8=AD=D8=A7=D9=83=D8=A7=D8=A9 =D8=AC=D9=84=D8=B3=D8=
=A7=D8=AA =D9=85=D8=AC=D9=84=D8=B3 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=
=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LT=
R" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;se=
rif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,&quot;sans-serif&quo=
t;;color:red">=D9=84=D9=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=
=D8=A7=D8=B3=D8=AA=D9=81=D8=B3=D8=A7=D8=B1</span></b><span dir=3D"LTR"></sp=
an></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,&quot;sans-serif&quo=
t;">=D9=88=D8=A8=D9=87=D8=B0=D9=87 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=
=A8=D8=A9 =D9=8A=D8=B3=D8=B9=D8=AF=D9=86=D8=A7 =D8=AF=D8=B9=D9=88=D8=AA=D9=
=83=D9=85 =D9=84=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =D9=88=D8=AA=D8=
=B9=D9=85=D9=8A=D9=85 =D8=AE=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =D8=B9=D9=84=D9=
=89
=D8=A7=D9=84=D9=85=D9=87=D8=AA=D9=85=D9=8A=D9=86 =D8=A8=D9=85=D9=80=D9=80=
=D9=88=D8=B6=D9=80=D9=88=D8=B9=C2=A0</span></b><b><span lang=3D"AR-EG" styl=
e=3D"font-size:16pt;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=
=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=
=D9=81=D9=8A=D8=A9=C2=A0</span></b><b><span lang=3D"AR-SA" style=3D"font-si=
ze:16pt;font-family:Arial,&quot;sans-serif&quot;">=D9=88=D8=A5=D9=81=D8=A7=
=D8=AF=D8=AA=D9=86=D8=A7 =D8=A8=D9=85=D9=86 =D8=AA=D9=82=D8=AA=D8=B1=D8=AD=
=D9=88=D9=86 =D8=AA=D9=88=D8=AC=D9=8A=D9=87 =D8=A7=D9=84=D8=AF=D8=B9=D9=88=
=D8=A9 =D9=84=D9=87=D9=85</span></b><span lang=3D"AR-SA"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,&quot;sans-serif&quo=
t;">=D9=84=D9=85=D8=B2=D9=8A=D8=AF =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B9=D9=
=84=D9=88=D9=85=D8=A7=D8=AA =D9=8A=D9=85=D9=83=D9=86=D9=83 =D8=A7=D9=84=D8=
=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=85=D8=B9 =D8=A3 / =D8=B3=D8=A7=D8=B1=D8=A9 =
=D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=A7=D8=AF =E2=80=93
=D9=86=D8=A7=D8=A6=D8=A8 =D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=
=D8=B1=D9=8A=D8=A8 =E2=80=93 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=
=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=
=A7=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></b><span lang=3D"AR-SA=
"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,&quot;sans-serif&quo=
t;">=D8=AC=D9=88=D8=A7=D9=84 =E2=80=93 =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=
=A8 :</span></b><span lang=3D"AR-SA"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font=
-size:16pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>0020106999439=
9 -00201062992510 - 00201096841626</span></b><span lang=3D"AR-SA"></span></=
p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">=C2=A0</span></p>

<h2 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:18pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><strong><span lang=3D"AR-=
SA" style=3D"font-weight:normal">=D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A7=D8=AA=
 =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=AF=D9=85=D8=A9 =D9=81=D9=8A
=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=
=D8=B3=D9=8A=D8=A9 =D9=84=D9=84=D9=81=D8=AA=D8=B1=D8=A9 =D9=85=D9=86 31 =D8=
=A7=D8=BA=D8=B3=D8=B7=D8=B3 =D8=A7=D9=84=D9=89 4 =D8=B3=D8=A8=D8=AA=D9=85=
=D8=A8=D8=B1 2025</span></strong><span dir=3D"LTR"></span></h2>

<table class=3D"gmail-MsoNormalTable" border=3D"0" cellpadding=3D"0">
 <thead>
  <tr>
   <td style=3D"padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><strong><span l=
ang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;font-family:Arial,&q=
uot;sans-serif&quot;">=D9=85</span></strong><b><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:107%"></span></b></p>
   </td>
   <td style=3D"padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><strong><span l=
ang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;font-family:Arial,&q=
uot;sans-serif&quot;">=D8=A7=D8=B3=D9=85
   =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D8=AA=D8=
=AF=D8=B1=D9=8A=D8=A8=D9=8A</span></strong><b><span dir=3D"LTR" style=3D"fo=
nt-size:18pt;line-height:107%"></span></b></p>
   </td>
   <td colspan=3D"2" style=3D"padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><strong><span l=
ang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;font-family:Arial,&q=
uot;sans-serif&quot;">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=88=D8=B1
   =D8=A7=D9=84=D8=B1=D8=A6=D9=8A=D8=B3=D9=8A=D8=A9</span></strong><b><span=
 dir=3D"LTR" style=3D"font-size:18pt;line-height:107%"></span></b></p>
   </td>
  </tr>
 </thead>
 <tbody><tr>
  <td style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;line-height:107%">1</span></p>
  </td>
  <td style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><strong><span la=
ng=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;font-family:Arial,&qu=
ot;sans-serif&quot;">=D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D8=A7=D9=
=84=D9=85=D8=AA=D9=82=D8=AF=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AD=D9=
=88=D9=83=D9=85=D8=A9
  =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=D8=A9 =D9=88=D8=A3=D9=81=D8=B6=
=D9=84 =D8=A7=D9=84=D9=85=D9=85=D8=A7=D8=B1=D8=B3=D8=A7=D8=AA</span></stron=
g><span dir=3D"LTR" style=3D"font-size:18pt;line-height:107%"></span></p>
  </td>
  <td colspan=3D"2" style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;line-height:107%">- </span><span lang=3D"AR-SA" s=
tyle=3D"font-size:18pt;line-height:107%;font-family:Arial,&quot;sans-serif&=
quot;">=D9=85=D8=A8=D8=A7=D8=AF=D8=A6 =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=
=D8=A9
  =D8=A7=D9=84=D8=B1=D8=B4=D9=8A=D8=AF=D8=A9</span><span dir=3D"LTR" style=
=3D"font-size:18pt;line-height:107%"><br>
  - </span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;fo=
nt-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=A3=D8=B7=D8=B1 =D8=
=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9
  =D9=84=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9</span><span dir=3D"LTR" style=
=3D"font-size:18pt;line-height:107%"><br>
  - </span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;fo=
nt-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=B4=D9=81=D8=A7=D9=
=81=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=A1=D9=84=D8=A9</spa=
n><span dir=3D"LTR" style=3D"font-size:18pt;line-height:107%"><br>
  - </span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;fo=
nt-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=B9=D9=84=D8=A7=D9=
=82=D8=A9 =D8=A8=D9=8A=D9=86 =D9=85=D8=AC=D9=84=D8=B3
  =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=AE=
=D8=A7=D8=B7=D8=B1</span><span dir=3D"LTR" style=3D"font-size:18pt;line-hei=
ght:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;line-height:107%">2</span></p>
  </td>
  <td style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><strong><span la=
ng=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;font-family:Arial,&qu=
ot;sans-serif&quot;">=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=
=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=AF=D9=85=D8=A9 =
=D9=81=D9=8A =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9
  =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=D8=A9</span></strong><span dir=
=3D"LTR" style=3D"font-size:18pt;line-height:107%"></span></p>
  </td>
  <td colspan=3D"2" style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;line-height:107%">- </span><span lang=3D"AR-SA" s=
tyle=3D"font-size:18pt;line-height:107%;font-family:Arial,&quot;sans-serif&=
quot;">=D8=A7=D9=84=D8=B1=D8=A8=D8=B7 =D8=A8=D9=8A=D9=86 =D8=A7=D9=84=D8=AD=
=D9=88=D9=83=D9=85=D8=A9
  =D9=88=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A7=D8=B3=
=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9</span><span dir=3D"LTR" st=
yle=3D"font-size:18pt;line-height:107%"><br>
  - </span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;fo=
nt-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=
=85=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1
  =D9=88=D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=D8=A7=D9=84</span><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:=
18pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>
  (GRC)<br>
  - </span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;fo=
nt-family:Arial,&quot;sans-serif&quot;">=D8=A5=D8=B7=D8=A7=D8=B1 =D8=A7=D9=
=84=D8=AD=D9=88=D9=83=D9=85=D8=A9
  =D8=A7=D9=84=D9=81=D8=B9=D8=A7=D9=84</span><span dir=3D"LTR" style=3D"fon=
t-size:18pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;line-height:107%">3</span></p>
  </td>
  <td style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><strong><span la=
ng=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;font-family:Arial,&qu=
ot;sans-serif&quot;">=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=B4=D8=
=B1=D9=83=D8=A7=D8=AA =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=
=85=D8=AE=D8=A7=D8=B7=D8=B1
  =D9=88=D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=D8=A7=D9=84</span></strong><sp=
an dir=3D"LTR" style=3D"font-size:18pt;line-height:107%"></span></p>
  </td>
  <td colspan=3D"2" style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;line-height:107%">- </span><span lang=3D"AR-SA" s=
tyle=3D"font-size:18pt;line-height:107%;font-family:Arial,&quot;sans-serif&=
quot;">=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A7=
=D8=AA
  =D9=88=D8=A3=D8=AF=D9=88=D8=A7=D8=B1 =D8=A7=D9=84=D9=85=D8=AC=D8=A7=D9=84=
=D8=B3</span><span dir=3D"LTR" style=3D"font-size:18pt;line-height:107%"><b=
r>
  - </span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;fo=
nt-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=AA=D8=AD=D9=83=D9=
=85 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1
  =D9=88=D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=D8=A7=D9=84</span><span dir=3D=
"LTR" style=3D"font-size:18pt;line-height:107%"><br>
  - </span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;fo=
nt-family:Arial,&quot;sans-serif&quot;">=D8=B3=D9=8A=D8=A7=D8=B3=D8=A7=D8=
=AA =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9
  =D8=A7=D9=84=D8=AF=D8=A7=D8=AE=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR" =
style=3D"font-size:18pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;line-height:107%">4</span></p>
  </td>
  <td style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><strong><span la=
ng=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;font-family:Arial,&qu=
ot;sans-serif&quot;">=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=88=D8=
=A7=D9=84=D8=A7=D8=A8=D8=AA=D9=83=D8=A7=D8=B1 =D8=A7=D9=84=D8=B1=D9=82=D9=
=85=D9=8A =D9=84=D9=85=D8=AC=D8=A7=D9=84=D8=B3
  =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9</span></strong><span dir=3D"LT=
R" style=3D"font-size:18pt;line-height:107%"></span></p>
  </td>
  <td colspan=3D"2" style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;line-height:107%">- </span><span lang=3D"AR-SA" s=
tyle=3D"font-size:18pt;line-height:107%;font-family:Arial,&quot;sans-serif&=
quot;">=D8=AF=D9=88=D8=B1 =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=81=
=D9=8A
  =D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A=
</span><span dir=3D"LTR" style=3D"font-size:18pt;line-height:107%"><br>
  - </span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;fo=
nt-family:Arial,&quot;sans-serif&quot;">=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=
=A7=D8=AA =D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1
  =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=
=A7=D9=84=D8=A3=D9=85=D8=A7=D9=86=D8=A9 =D8=A7=D9=84=D8=B9=D8=A7=D9=85=D8=
=A9 =D9=84=D9=84=D9=85=D8=AC=D9=84=D8=B3</span><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:107%"><br>
  - </span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;fo=
nt-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=A3=D8=B7=D8=B1 =D8=
=A7=D9=84=D8=AA=D9=86=D8=B8=D9=8A=D9=85=D9=8A=D8=A9
  =D9=84=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=
=D8=A7=D8=B9=D9=8A</span><span dir=3D"LTR" style=3D"font-size:18pt;line-hei=
ght:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;line-height:107%">5</span></p>
  </td>
  <td style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><strong><span la=
ng=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;font-family:Arial,&qu=
ot;sans-serif&quot;">=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=B4=D8=
=B1=D9=83=D8=A7=D8=AA =D9=81=D9=8A =D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=B9 =D8=
=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A</span></strong><span dir=3D"LTR" style=3D=
"font-size:18pt;line-height:107%"></span></p>
  </td>
  <td style=3D"padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;line-height:107%">- </span><span lang=3D"AR-SA" s=
tyle=3D"font-size:18pt;line-height:107%;font-family:Arial,&quot;sans-serif&=
quot;">=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=
=D8=A7=D8=AA
  =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR" style=
=3D"font-size:18pt;line-height:107%"><br>
  - </span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;fo=
nt-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=
=AB=D8=A7=D9=84 =D9=84=D9=84=D9=88=D8=A7=D8=A6=D8=AD
  =D8=A7=D9=84=D8=A8=D9=86=D9=88=D9=83 =D8=A7=D9=84=D9=85=D8=B1=D9=83=D8=B2=
=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:18pt;line-height:10=
7%"><br>
  - </span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:107%;fo=
nt-family:Arial,&quot;sans-serif&quot;">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=
=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1
  =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=D8=A9</span><span dir=3D"LTR" =
style=3D"font-size:18pt;line-height:107%"></span></p>
  </td>
 </tr>
</tbody></table>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR" =
style=3D"font-size:18pt;line-height:107%">=C2=A0</span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZK%3DwZ2j4H0fwLDQyj0%3D32CAEA4K6r%3D208%3D_4bDxDpMokUw%40mai=
l.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.c=
om/d/msgid/kasan-dev/CADj1ZK%3DwZ2j4H0fwLDQyj0%3D32CAEA4K6r%3D208%3D_4bDxDp=
MokUw%40mail.gmail.com</a>.<br />

--000000000000711f5f063d0a5bb9--
