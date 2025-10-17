Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBS53ZLDQMGQEEVM2FIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DB5CBEB68C
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Oct 2025 21:49:34 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-36ac8376af1sf15081401fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Oct 2025 12:49:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760730573; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZYS09Y5vT64SAXMNrWHyiF2r/3c3VlIrOK9WNXvQfZ79nhNrgJPXUmDJmEXRFokz7G
         cs90gpsxVgxd1AjmN0/pKHtoQAVv7flZGrWDu5srngITCZFeHQHRbWRasMjl6+8PJOBb
         BNrfRe0/qnvrpfNwLM8LZjqE2U8aYbUNtcvl51KdtZp6cyfY1zH3MowZOBJTIjsuWjq2
         fhx7blCwmwag243A5UpNWeAJNmBB8mZT80uXf8pIUf+1ENnlupa/nPF2RLJRf14+1hM7
         kyndPx8IXvJ+19MUHNEIV6gPAXzeUviiUkzRTM98P6r5CqUrOBiSw5QpqViU9W9ojoEb
         93vQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=rKizWiQOUf67RqJF7K8JIByCTTaYxSW/vd3z7BR6jBI=;
        fh=Kfuirb5w/LhaM5YfMx0uAOuVz1g7aChJvL3/dCUrw6Q=;
        b=CeTW/B5AzAJgYclxwKuePI5ykKB4+R+6OdmthmwtVeZ0cGp/Xd+m3zFUL9xji2Irj4
         hBQI7Besp72lb8sJ3HFwsCBGaUm/6M4/hFym7gvOAN+JNi80y69M3b+v+pdZnE092cTY
         GwQdHJfmJ1iC3fuD+MZkJ/p3MBE6YxB2NYZ0xOvmL02Bcu5TiSwTkfZHa00UKtgAseis
         6t6XpKCF1OSVXcssiH2vM71aimirKnhUkFYupjVGJeoThLhob8Vkz/H8y0LpTRvPCmMx
         iBW8e7nUX/MuXNRvsd6bdDebJ0tmgfq/YKwH7O1favShC4DV7SjaFRQ16OaSvqDRzBNW
         vCRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UAEYej94;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760730573; x=1761335373; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rKizWiQOUf67RqJF7K8JIByCTTaYxSW/vd3z7BR6jBI=;
        b=XUAuO15xn9QLWSnMmdQagq/NSr50A+x9RjXbmAht4RWrFmqF68n4ppVO+Y7o1NK5Rl
         +Do25RZPeKcQEZ7IY+CvRe/WEmK74KcPS/8R0O4WYhiHV+a7JvYBO4NYuqh1Z7yDs9io
         x6M3Lh7pwGT+7111t+VKtXeIItmliJxfuBl8x30QFeaxQuyFgVK33nBJCC4Ot+MTkvhu
         d6emHe7Kextdo3TDo6xZoUrbBunB4q9eqLPF5C79Z609dfTkVvGfX1Y60dOTrx3/sgNl
         wdgFrwEY5ydql+9vbmZrVGrOnxaWCemd3lQ62gYi6LDeXwkYJNeRRlf8MMxeOB9YGshw
         MjMQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760730573; x=1761335373; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=rKizWiQOUf67RqJF7K8JIByCTTaYxSW/vd3z7BR6jBI=;
        b=YuPEx23WhtWPIaDxILaiwoQk8RY29iPLLzW2WxiCUWbtaurGr86rbCGvUTxApdZe5p
         a5YBRyywdIc7onWIzvevUUVRfpgaUWPTF4sYfFiXvKqNN5AurPOEuO5WmTaC6UW/VYzl
         a/7t4lUtJBbVKN7EdjWbwKLAGaFkmVgkac9SObZgVpXnLminCX8e4D5c9aiuHTQx4xmB
         0yru2qFELixG1AUbIg8D1nDd4VmNyFer+4hsjsegrQw9S92xcBnnOaJfKnzGihOPGVx5
         y3sxRbDDr2yXIP+B/o/IGMgX+ZVikGG7WJlE0HV0crgPglM3K/pDW6lPBZcEb5ew/A9a
         86xA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760730573; x=1761335373;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rKizWiQOUf67RqJF7K8JIByCTTaYxSW/vd3z7BR6jBI=;
        b=k+0u0f2Lnq9KQZUHI33m8skyF6zgrI9W+MSMY5Aba2wO/ML6wzUB1/v28FBZi2RKmj
         JLh8KzYrikARa4eJWEPwuJQ8LGePZ6keB9dJuxjjKDh3w3vvrEUYj7UxXMc85fT1D9mw
         4ORRA1aM7LibR4dC3+KO64elJ1U723q+jGU7kBp434mTiFuNXEOT504Z/9d1VJ5nswiR
         MGwmcmaRcAtJvF32APDOXLGqWolWMUQCp1iEFXJZl4NQFZWQHCN4x86rHT9oYrYv+eRU
         uVZQzOjUITQ6pRPYbPUVoT0Db+Ux8K5lrUCs3PmLtUVHkT+SciMPVwrLKMWMhpRUZ/e+
         TnIw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVCEPlr8v2UKU0qhTL9v6l2o4JSxtRYUxKIg5Tuq26V4eZseTgJc3SGZVFlPc6LYa/simMUSA==@lfdr.de
X-Gm-Message-State: AOJu0YwefhhGn2pvwOp1m4zxDYd1vGqng613/kHJG6bhR544kySi5Ton
	s7TfMS2atWNu8JMIwshawwqqcZm++JZ2iCrW34qFkZcrz3ssu5xLWEpH
X-Google-Smtp-Source: AGHT+IHgtVAxFls8l8aC1hsO5RCwqbVkxBOIC1jaiSlMxJ14InOrs6t6ENUOdJM47dZMXBFrUchoKQ==
X-Received: by 2002:a05:651c:198f:b0:375:d8c8:fe2e with SMTP id 38308e7fff4ca-37797a397c4mr16737641fa.26.1760730572689;
        Fri, 17 Oct 2025 12:49:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6bBoRxsdAcmDHMbaYJCi4bwICll4JbbSxnAGzs6SzdxQ=="
Received: by 2002:a2e:8603:0:b0:36e:6146:66fe with SMTP id 38308e7fff4ca-37787710b40ls4211621fa.1.-pod-prod-09-eu;
 Fri, 17 Oct 2025 12:49:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXf/wKAi91kzLFKouusb0oU3giegNB2fbajdzXc5cYIZD4FuLsZ9TQD1BGdG6cObsgOUCcJg47sQm8=@googlegroups.com
X-Received: by 2002:a05:651c:12c3:b0:36b:b439:93cc with SMTP id 38308e7fff4ca-37797a798f1mr15354731fa.37.1760730569706;
        Fri, 17 Oct 2025 12:49:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760730569; cv=none;
        d=google.com; s=arc-20240605;
        b=ZYNFhcqa48IBefjywwjGojRmFdTyb61sdvxaVzAmAYMYCdDcL28uqq/BaAcHRtSy5X
         p8gk9ELrOteeM5aLY6N7TLS46MZrIXXeH1ko6VgPbzuLVWU9W48MA30esCJxRzLtFG11
         KCD57owjRZdljd+jdiHS/06gL5R8mk6b/fMJLXmkGXJHySewcpRMsNtjEHhNJzNh79Ri
         hn+2J4MaE9/qrnaHZhHvwM43BkTe4qiNaeV69XOiRwKi7qZe9jPQS41CMMpSn0KDzq53
         WKIkjrsX3HMX/i9VIprSvkECuHMIE7hBEDvW+5rpYnzXhR+ColcfsJjS5mPunNYxNX8F
         q8Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=E1Dr0Q/tS9HjdEMPPAC/D6MAi0p/3cKm+S+H7+BQC0A=;
        fh=oDKsq7NM0RnjgCk8eOPgnsjeGgwF86aE/4tdb+9amG8=;
        b=CMi4CXn4v0v6D91aZsZ0tADzkXb+HUkcSy/sv0y+uD9dbKQ4qwHqK5NP8uvmqGxcg6
         Ct7FQ2Ox1hGoo8SMs2jfxuwCC2IAMK+rvOJji6qlqz+Wbfxz8O9yzT8drE5ybIgZm9Lx
         t6HvKNtK4HrOm2ygmov0WACrbVOh10BqARZFeNLfNebdniwdzVcrtYWRNK/uCsWeMBjV
         R6VGaP2FiU6iYJQAjMjoxBSCYSeuooK+jB+XGdDHjAs7+ZiZkeUMHuhleCfkr4DEggl2
         NCRPNfFM6T6AhJ8qzFLL38gpqe8/XqptWGcozrno9xXMNNcWyQJQ+89ziknofeoxfAV2
         lY8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UAEYej94;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x630.google.com (mail-ej1-x630.google.com. [2a00:1450:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-377a963fa17si459641fa.3.2025.10.17.12.49.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Oct 2025 12:49:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::630 as permitted sender) client-ip=2a00:1450:4864:20::630;
Received: by mail-ej1-x630.google.com with SMTP id a640c23a62f3a-b5e19810703so343436766b.2
        for <kasan-dev@googlegroups.com>; Fri, 17 Oct 2025 12:49:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW9a+gLte99Vt4iXcxd2PsoiZTqFQWhHyvpvtW0vKOIoI6sPJRwtHfaGPI0Ms2qj5fznFBqdBUBzUQ=@googlegroups.com
X-Gm-Gg: ASbGncvRJf6CJqUawqYBsnB+FJ78IXsIZ6QYB2hkssYD7pjTo9p83bXKWhPkya2V9tP
	+WmnUym+jGuluHURErsKC1GpWdSVEJyk2bQrE2TjGqJb4qqQBECIQ0wVyffV5fYUJc5CpKDYLZD
	6d5pNs3RoNjzp71W3fjPwO5/6a6v2ydAXy2z4FfFyfzC9Wne/2aoHNYc3HBWyiwhcr7/PWvCgrn
	AGrZT1ECbsXZ4+TvKRkziVPzIOT/QG22LwU43BT7qYmPJQLQlNjSCCpi75WkCbvJpdHVyBFaCDf
	SpE=
X-Received: by 2002:a17:906:c105:b0:b41:cd32:a434 with SMTP id
 a640c23a62f3a-b64750108b6mr526301566b.65.1760730568531; Fri, 17 Oct 2025
 12:49:28 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Fri, 17 Oct 2025 22:49:15 +0300
X-Gm-Features: AS18NWBTnmEJlgaR_cGNXDQoJYRhLJRKo7_X77bUixKhS--luqRhYs0_5Uc1XPw
Message-ID: <CADj1ZKkH_86GeNSX0SM0+tKo8ejU7LjeDtDsz47t2aGMaMTbzw@mail.gmail.com>
Subject: =?UTF-8?B?2KfZhNmF2YbYtNii2KogI9in2YTYr9in2LFf2KfZhNi52LHYqNmK2Klf2YTZhNiq2YbZhQ==?=
	=?UTF-8?B?2YrYqV/Yp9mE2KXYr9in2LHZitipICPYrdmI2YPZhdipX9in2YTZhdik2LPYs9in2KogI9in2YTYp9iz?=
	=?UTF-8?B?2KrYr9in2YXYqV/Yp9mE2LXZhtin2LnZitipICPYp9mE2LXZhtin2LnYqV/Yp9mE2LDZg9mK2KkgI9it?=
	=?UTF-8?B?2YjZg9mF2KlfMjAyNSDZhtit2LHYtSDYudmE2Ykg2KjZhtin2KEg2LnZhNin2YLYqSDZiNir2YrZgtip?=
	=?UTF-8?B?INmF2Lkg2LTYsdmD2KfYoSDYp9mE2KrYr9ix2YrYqCDZg9mF2Kcg2YbYrdix2LUg2LnZhNmJINiq2LU=?=
	=?UTF-8?B?2YXZitmFINij2K3Yr9irINio2LHYp9mF2Kwg2KfZhNiq2K/YsdmK2Kgg2YjYp9mE2KrYt9mI2YrYsSA=?=
	=?UTF-8?B?2KjYtNmD2YQg2YXYs9iq2YXYsSDZhNi22YXYp9mGINix2YHYuSDYo9iv2KfYoSDYp9mE2YXYtNin2LE=?=
	=?UTF-8?B?2YPZitmGINmB2Yog2KzZhdmK2Lkg2YLYt9in2LnYp9iqINin2YTYudmF2YQg2KfZhNmC2YrYp9iv2Kkg?=
	=?UTF-8?B?2YjYp9mE2K3ZiNmD2YXYqSDZgdmKINin2YTZhdmG2LTYotiqINin2YTYtdmG2KfYudmK2KkgTGVhZGVy?=
	=?UTF-8?B?c2hpcCAmIEdvdmVybmFuY2UgaW4gSW5kdXN0cmlhbCBPcmdhbml6YXRpb25zINmE2YTZgdiq2LHYqSA=?=
	=?UTF-8?B?2YXZhiAyNi0gMzAg2KfZg9iq2YDZgNmA2YDZgNmA2YDZgNmA2YjYqNixIDIwMjUg2YUg2KfZhNmC2Kc=?=
	=?UTF-8?B?2YfYsdipIOKAkyDYrNmF2YfZiNix2YrYqSDZhdi12LEg2KfZhNi52LHYqNmK2Kkg4oCTINin2YTZhdmC?=
	=?UTF-8?B?2LEg2KfZhNin2K/Yp9ix2Yog2YTZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSA=?=
	=?UTF-8?B?2KfZhNin2K/Yp9ix2YrYqSDYtNmH2KfYr9ipINmF2YfZhtmK2Kkg2YXYudiq2YXYr9ipIOKAkyDZhdmI?=
	=?UTF-8?B?2KvZgtipINmI2KjYp9i52KrZhdin2K8g2K/ZiNmE2Yog2YXYudiq2LHZgSDYqNmH2Kcg2YHZiiDZg9in?=
	=?UTF-8?B?2YHYqSDYp9mE2K/ZiNmEINin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2Kc=?=
	=?UTF-8?B?2YTYp9iv2KfYsdmK2Kkg4oCTIEFIQUQg2YXYuSDYp9iq2KfYrdipINin2YTYr9ix2Kfvv70=?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000015276306416008bb"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UAEYej94;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::630
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

--00000000000015276306416008bb
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2KfZhNmF2YbYtNii2KogI9in2YTYr9in2LFf2KfZhNi52LHYqNmK2Klf2YTZhNiq2YbZhdmK2Klf
2KfZhNil2K/Yp9ix2YrYqQ0KI9it2YjZg9mF2Klf2KfZhNmF2KTYs9iz2KfYqiAj2KfZhNin2LPY
qtiv2KfZhdipX9in2YTYtdmG2KfYudmK2KkNCiPYp9mE2LXZhtin2LnYqV/Yp9mE2LDZg9mK2Kkg
I9it2YjZg9mF2KlfMjAyNQ0KDQoq2YbYrdix2LUg2LnZhNmJINio2YbYp9ihINi52YTYp9mC2Kkg
2YjYq9mK2YLYqSDZhdi5INi02LHZg9in2KEg2KfZhNiq2K/YsdmK2KgqDQoNCirZg9mF2Kcg2YbY
rdix2LUg2LnZhNmJINiq2LXZhdmK2YUg2KPYrdiv2Ksg2KjYsdin2YXYrCDYp9mE2KrYr9ix2YrY
qCDZiNin2YTYqti32YjZitixINio2LTZg9mEINmF2LPYqtmF2LEgKg0KDQoq2YTYttmF2KfZhiDY
sdmB2Lkg2KPYr9in2KEg2KfZhNmF2LTYp9ix2YPZitmGINmB2Yog2KzZhdmK2Lkg2YLYt9in2LnY
p9iqINin2YTYudmF2YQqDQoNCtin2YTZgtmK2KfYr9ipINmI2KfZhNit2YjZg9mF2Kkg2YHZiiDY
p9mE2YXZhti02KLYqiDYp9mE2LXZhtin2LnZitipIExlYWRlcnNoaXAgJiBHb3Zlcm5hbmNlIGlu
IEluZHVzdHJpYWwNCk9yZ2FuaXphdGlvbnMg2YTZhNmB2KrYsdipINmF2YYgMjYtIDMwINin2YPY
qtmA2YDZgNmA2YDZgNmA2YDZgNmI2KjYsSAyMDI1INmFINin2YTZgtin2YfYsdipIOKAkyDYrNmF
2YfZiNix2YrYqSDZhdi12LENCtin2YTYudix2KjZitipIOKAkyDYp9mE2YXZgtixINin2YTYp9iv
2KfYsdmKINmE2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNin2K/Y
p9ix2YrYqQ0KDQoq2LTZh9in2K/YqSDZhdmH2YbZitipINmF2LnYqtmF2K/YqSDigJMg2YXZiNir
2YLYqSDZiNio2KfYudiq2YXYp9ivINiv2YjZhNmKKiAq2YXYudiq2LHZgSDYqNmH2Kcg2YHZiiDZ
g9in2YHYqSDYp9mE2K/ZiNmEKg0KDQoq2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZ
htmF2YrYqSDYp9mE2KfYr9in2LHZitipIOKAkyAqKkFIQUQqDQrZhdi5INin2KrYp9it2Kkg2KfZ
hNiv2LHYp9iz2Kkg2KfZiNmGINmE2KfZitmGINio2LHYs9mI2YUg2YXYrtmB2LbYqSDZgdmKINit
2KfZhCDYqti52LDYsSDYp9mE2K3YttmI2LEg2KfZhNij2YfYr9in2YE6INiq2YXZg9mK2YYNCtin
2YTZgtmK2KfYr9in2Kog2KfZhNi12YbYp9i52YrYqSDZhdmGINiq2LfYqNmK2YIg2YXYqNin2K/Y
piDYp9mE2K3ZiNmD2YXYqS4g2KrYudiy2YrYsiDYp9mE2LTZgdin2YHZitipINmI2KfZhNix2YLY
p9io2Kkg2K/Yp9iu2YQNCtin2YTZhdmG2LTYotiqINin2YTYtdmG2KfYudmK2KkuINmF2YjYp9ih
2YXYqSDYp9iz2KrYsdin2KrZitis2YrYp9iqINin2YTZgtmK2KfYr9ipINmF2Lkg2YXYqti32YTY
qNin2Kog2KfZhNit2YjZg9mF2Kkg2KfZhNit2K/Zitir2KkuINix2YHYuQ0K2YPZgdin2KHYqSDY
p9iq2K7Yp9iwINin2YTZgtix2KfYsSDZiNiq2K3ZgtmK2YIg2KfZhNin2LPYqtiv2KfZhdipINin
2YTZhdik2LPYs9mK2KkuINin2YTZgdim2Kkg2KfZhNmF2LPYqtmH2K/ZgdipOiDYp9mE2YXYr9ix
2KfYoQ0K2KfZhNiq2YbZgdmK2LDZitmI2YYg2YjYo9i52LbYp9ihINmF2KzYp9mE2LMg2KfZhNil
2K/Yp9ix2KkuINmF2K/Ysdin2KEg2KfZhNmF2LXYp9mG2Lkg2YjYp9mE2YXZhti02KLYqiDYp9mE
2LXZhtin2LnZitipLiDZhdiz2KTZiNmE2YgNCtin2YTYrNmI2K/YqSDZiNin2YTYrdmI2YPZhdip
INmI2KfZhNin2YTYqtiy2KfZhS4g2KfZhNmC2YrYp9iv2KfYqiDYp9mE2KXYr9in2LHZitipINmB
2Yog2KfZhNmC2LfYp9i5INin2YTYtdmG2KfYudmKLiDZhdit2KfZiNixDQrYp9mE2KjYsdmG2KfZ
hdisOiDZhdiv2K7ZhCDYpdmE2Ykg2KfZhNmC2YrYp9iv2Kkg2KfZhNi12YbYp9i52YrYqSDZiNin
2YTYrdmI2YPZhdipINin2YTYsdi02YrYr9ipLiDYp9iz2KrYsdin2KrZitis2YrYp9iqINin2YTZ
gtmK2KfYr9ipDQrZgdmKINio2YrYptipINi12YbYp9i52YrYqSDZhdiq2LrZitix2KkuINmF2KjY
p9iv2KYg2KfZhNit2YjZg9mF2Kkg2YjYqti32KjZitmC2KfYqtmH2Kcg2YHZiiDYp9mE2YXYtdin
2YbYuS4g2KfZhNi02YHYp9mB2YrYqSDZiNil2K/Yp9ix2KkNCtin2YTZhdiu2KfYt9ixINmB2Yog
2KfZhNmC2LfYp9i5INin2YTYtdmG2KfYudmKLiDYp9mE2KrYrNin2LHYqCDYp9mE2K/ZiNmE2YrY
qSDYp9mE2LHYp9im2K/YqSDZgdmKINit2YjZg9mF2Kkg2KfZhNmF2LXYp9mG2LkuINii2YTZitin
2KoNCtiq2LfZiNmK2LEg2KfZhNij2K/Yp9ihINin2YTZhdik2LPYs9mKINmI2LbZhdin2YYg2KfZ
hNin2LPYqtiv2KfZhdipLg0KDQoq2YjYqNmH2LDZhyDYp9mE2YXZhtin2LPYqNipINmK2LPYudiv
2YbYpyDYr9i52YjYqtmD2YUg2YTZhNmF2LTYp9ix2YPYqSDZiNiq2LnZhdmK2YUg2K7Yt9in2KjZ
htinINi52YTZiSDYp9mE2YXZh9iq2YXZitmGDQrYqNmF2YDZgNmI2LbZgNmI2LkgKirYp9mE2LTZ
h9in2K/YqSDYp9mE2KfYrdiq2LHYp9mB2YrYqSAqKtmI2KXZgdin2K/YqtmG2Kcg2KjZhdmGINiq
2YLYqtix2K3ZiNmGINiq2YjYrNmK2Ycg2KfZhNiv2LnZiNipINmE2YfZhSoNCg0KKtmE2YXYstmK
2K8g2YXZhiDYp9mE2YXYudmE2YjZhdin2Kog2YrZhdmD2YbZgyDYp9mE2KrZiNin2LXZhCDZhdi5
INijIC8g2LPYp9ix2Kkg2LnYqNivINin2YTYrNmI2KfYryDigJPZhdiv2YrYsSDYp9mE2KrYr9ix
2YrYqCDigJMNCtin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNin
2K/Yp9ix2YrYqSoNCg0KKiAgICAgICAgICAgICAgICAgICAgICAgICDYrNmI2KfZhCDigJMg2YjY
p9iq2LMg2KfYqCA6Kg0KDQoqMDAyMDEwNjk5OTQzOTkgLTAwMjAxMDYyOTkyNTEwIC0gMDAyMDEw
OTY4NDE2MjYqDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICDYp9mE2K/ZiNix2KfY
qiDYp9mE2KrYr9ix2YrYqNmK2KkgKDI2IOKAkyAzMCDYo9mD2KrZiNio2LENCjIwMjXZhSkg8J+U
uSAq2KfZhNil2K/Yp9ix2KkNCtmI2KfZhNmC2YrYp9iv2KkgKiDYp9mE2YLZitin2K/YqSDYp9mE
2LDZg9mK2Kkg2YjYpdiv2KfYsdipINmB2LHZgiDYp9mE2LnZhdmEINi52KfZhNmK2Kkg2KfZhNij
2K/Yp9ihINin2YTYqtiu2LfZiti3INin2YTYp9iz2KrYsdin2KrZitis2YoNCtio2KfYs9iq2K7Y
r9in2YUg2YXYpNi02LHYp9iqINin2YTYo9iv2KfYoSBLUEkg2KXYr9in2LHYqSDYp9mE2KrYutmK
2YrYsSDYp9mE2YXYpNiz2LPZiiDZiNin2YTYqtit2YjZhCDYp9mE2LHZgtmF2Yog8J+UuSAq2KfZ
hNmF2K3Yp9iz2KjYqQ0K2YjYp9mE2YXYp9mE2YrYqSog2KfZhNmF2K3Yp9iz2KjYqSDYp9mE2YXY
p9mE2YrYqSDYp9mE2YXYqtmC2K/ZhdipINmI2YHZgiBJRlJTINin2YTYqtiv2YLZitmCINin2YTY
r9in2K7ZhNmKINmI2YXZg9in2YHYrdipDQrYp9mE2KfYrdiq2YrYp9mEINin2YTZhdin2YTZiiDY
p9mE2KrYrti32YrYtyDYp9mE2YXYp9mE2Yog2YjYpdi52K/Yp9ivINin2YTZhdmI2KfYstmG2KfY
qiDwn5S5ICrYp9mE2K3ZiNmD2YXYqSDZiNin2YTZgtin2YbZiNmGKiDYp9mE2K3ZiNmD2YXYqQ0K
2YjYp9mE2LTZgdin2YHZitipINmB2Yog2KfZhNmF2KTYs9iz2KfYqiDYpdiv2KfYsdipINin2YTY
udmC2YjYryDZiNin2YTZhdmG2KfYsti52KfYqiDYp9mE2YLYp9mG2YjZhtmK2Kkg2KfZhNin2YXY
qtir2KfZhCDYp9mE2YXYpNiz2LPZig0K2YjYp9mE2KfZhNiq2LLYp9mFINio2KfZhNmC2YjYp9mG
2YrZhiDYp9mE2K/ZiNmE2YrYqSDwn5S5ICrYp9mE2YXYtNiq2LHZitin2Kog2YjYp9mE2YTZiNis
2LPYqtmK2KfYqiog2KXYr9in2LHYqSDYs9mE2KfYs9mEINin2YTYpdmF2K/Yp9ivDQrZiNin2YTY
qtmI2LHZitivINin2YTYrdiv2YrYq9ipINin2YTYp9iz2KrYsdin2KrZitis2YrYp9iqINin2YTZ
hdiq2YLYr9mF2Kkg2YHZiiDYp9mE2YXYtNiq2LHZitin2Kog2KfZhNit2YPZiNmF2YrYqSDYpdiv
2KfYsdipINin2YTZhdiu2KfYstmGDQrZiNin2YTZhdiz2KrZiNiv2LnYp9iqINmI2KrYrdmE2YrZ
hCDYp9mE2YXYrtiy2YjZhiDwn5S5ICrYp9mE2KPZhdmGINmI2KfZhNiz2YTYp9mF2Kkg2YjYp9mE
2LXYrdipINin2YTZhdmH2YbZitipKiDYp9mE2LPZhNin2YXYqQ0K2KfZhNmF2YfZhtmK2Kkg2YjZ
gdmCINmF2LnYp9mK2YrYsSBPU0hBINil2K/Yp9ix2Kkg2KfZhNmF2K7Yp9i32LEg2YjYp9mE2KPY
stmF2KfYqiDZgdmKINin2YTZhdmG2LTYotiqINin2YTYtdmG2KfYudmK2Kkg2KfZhNiz2YTYp9mF
2KkNCtmB2Yog2KfZhNiq2LnYp9mF2YQg2YXYuSDYp9mE2YXZiNin2K8g2KfZhNiu2LfYsdipIPCf
lLkgKtin2YTYqtit2YjZhCDYp9mE2LHZgtmF2Yog2YjYp9mE2KrZgtmG2YrYqSog2KfZhNiw2YPY
p9ihINin2YTYp9i12LfZhtin2LnZig0K2YjYqti32KjZitmC2KfYqtmHINmB2Yog2KfZhNil2K/Y
p9ix2Kkg2K3Zhdin2YrYqSDYp9mE2KjZitin2YbYp9iqINmI2KfZhNij2YXZhiDYp9mE2LPZitio
2LHYp9mG2Yog2KfZhNiq2K3ZhNmK2YTYp9iqINin2YTYqtmG2KjYpNmK2KkNCtio2KfYs9iq2K7Y
r9in2YUgUG93ZXIgQkkg2YhFeGNlbA0KDQotLSAKWW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBi
ZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAia2FzYW4tZGV2
IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdyb3VwIGFuZCBzdG9wIHJlY2Vpdmlu
ZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byBrYXNhbi1kZXYrdW5zdWJzY3JpYmVA
Z29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRpc2N1c3Npb24gdmlzaXQgaHR0cHM6Ly9n
cm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9DQURqMVpLa0hfODZHZU5TWDBTTTAl
MkJ0S284ZWpVN0xqZUR0RHN6NDd0MmFHTWFNVGJ6dyU0MG1haWwuZ21haWwuY29tLgo=
--00000000000015276306416008bb
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><h1 align=3D"center" dir=3D"RTL" style=3D"text-align:cente=
r;direction:rtl;unicode-bidi:embed;margin-right:0in;margin-left:0in;font-si=
ze:24pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:28pt">=D8=A7=D9=84=D9=85=D9=86=D8=B4=D8=A2=
=D8=AA </span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR" style=3D"font-size:28pt"><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span>#</span><span lang=3D"AR-SA" style=3D"font-size:28pt">=D8=A7=D9=84=
=D8=AF=D8=A7=D8=B1_=D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9_=D9=84=D9=84=
=D8=AA=D9=86=D9=85=D9=8A=D8=A9_=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=
=D8=A9</span><span dir=3D"LTR" style=3D"font-size:28pt"><br>
#</span><span lang=3D"AR-SA" style=3D"font-size:28pt">=D8=AD=D9=88=D9=83=D9=
=85=D8=A9_=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA </span><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-si=
ze:28pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>#</span><span la=
ng=3D"AR-SA" style=3D"font-size:28pt">=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AF=
=D8=A7=D9=85=D8=A9_=D8=A7=D9=84=D8=B5=D9=86=D8=A7=D8=B9=D9=8A=D8=A9</span><=
span dir=3D"LTR" style=3D"font-size:28pt"><br>
#</span><span lang=3D"AR-SA" style=3D"font-size:28pt">=D8=A7=D9=84=D8=B5=D9=
=86=D8=A7=D8=B9=D8=A9_=D8=A7=D9=84=D8=B0=D9=83=D9=8A=D8=A9 </span><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-si=
ze:28pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>#</span><span la=
ng=3D"AR-SA" style=3D"font-size:28pt">=D8=AD=D9=88=D9=83=D9=85=D8=A9_2025</=
span></h1>

<p class=3D"MsoNormal" align=3D"center" style=3D"text-align:center;line-hei=
ght:normal;margin:0in 0in 8pt;font-size:11pt;font-family:Calibri,&quot;sans=
-serif&quot;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"font-size:24pt;f=
ont-family:&quot;Sakkal Majalla&quot;;color:rgb(23,55,94)">=D9=86=D8=AD=D8=
=B1=D8=B5 =D8=B9=D9=84=D9=89 =D8=A8=D9=86=D8=A7=D8=A1 =D8=B9=D9=84=D8=A7=D9=
=82=D8=A9 =D9=88=D8=AB=D9=8A=D9=82=D8=A9 =D9=85=D8=B9 =D8=B4=D8=B1=D9=83=D8=
=A7=D8=A1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8</span></b><span style=
=3D"font-size:10.5pt;font-family:Helvetica,&quot;sans-serif&quot;"></span><=
/p>

<p class=3D"MsoNormal" align=3D"center" style=3D"text-align:center;line-hei=
ght:normal;margin:0in 0in 8pt;font-size:11pt;font-family:Calibri,&quot;sans=
-serif&quot;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"font-size:24pt;f=
ont-family:&quot;Sakkal Majalla&quot;;color:rgb(23,55,94)">=D9=83=D9=85=D8=
=A7 =D9=86=D8=AD=D8=B1=D8=B5 =D8=B9=D9=84=D9=89 =D8=AA=D8=B5=D9=85=D9=8A=D9=
=85 =D8=A3=D8=AD=D8=AF=D8=AB =D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D8=
=AA=D8=AF=D8=B1=D9=8A=D8=A8 =D9=88=D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=
=B1
=D8=A8=D8=B4=D9=83=D9=84 =D9=85=D8=B3=D8=AA=D9=85=D8=B1 </span></b><span st=
yle=3D"font-size:10.5pt;font-family:Helvetica,&quot;sans-serif&quot;"></spa=
n></p>

<p class=3D"MsoNormal" align=3D"center" style=3D"text-align:center;line-hei=
ght:normal;margin:0in 0in 8pt;font-size:11pt;font-family:Calibri,&quot;sans=
-serif&quot;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"font-size:24pt;f=
ont-family:&quot;Sakkal Majalla&quot;;color:rgb(23,55,94)">=D9=84=D8=B6=D9=
=85=D8=A7=D9=86 =D8=B1=D9=81=D8=B9 =D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=D9=84=D9=
=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D9=81=D9=8A =D8=AC=D9=85=D9=8A=D8=
=B9 =D9=82=D8=B7=D8=A7=D8=B9=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D9=85=D9=84</sp=
an></b><span style=3D"font-size:10.5pt;font-family:Helvetica,&quot;sans-ser=
if&quot;"></span></p>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR" style=
=3D"font-size:28pt"><br>
</span><span lang=3D"AR-SA" style=3D"font-size:28pt">=D8=A7=D9=84=D9=82=D9=
=8A=D8=A7=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=
=81=D9=8A =D8=A7=D9=84=D9=85=D9=86=D8=B4=D8=A2=D8=AA
=D8=A7=D9=84=D8=B5=D9=86=D8=A7=D8=B9=D9=8A=D8=A9</span><span dir=3D"LTR" st=
yle=3D"font-size:28pt"></span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR" style=
=3D"font-size:16pt">Leadership &amp; Governance in
Industrial Organizations</span></h1>

<h2 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin:2pt 0in 0.0001pt;line-height:107%;break-after:avoi=
d;font-size:13pt;font-family:&quot;Calibri Light&quot;,&quot;sans-serif&quo=
t;;color:rgb(46,116,181);font-weight:normal"><span lang=3D"AR-EG" style=3D"=
font-size:28pt;line-height:107%;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D9=84=D9=84=D9=81=D8=AA=D8=B1=D8=A9 =D9=85=D9=86 </span><s=
pan lang=3D"AR-EG" style=3D"font-size:22pt;line-height:107%;font-family:&qu=
ot;Times New Roman&quot;,&quot;serif&quot;">26</span><span lang=3D"AR-EG" s=
tyle=3D"font-size:28pt;line-height:107%;font-family:&quot;Times New Roman&q=
uot;,&quot;serif&quot;">- </span><span lang=3D"AR-EG" style=3D"font-size:22=
pt;line-height:107%;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">30</span><span lang=3D"AR-EG" style=3D"font-size:28pt;line-height:107%;=
font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"> =D8=A7=D9=83=D8=
=AA=D9=80=D9=80=D9=80=D9=80=D9=80=D9=80=D9=80=D9=80=D9=80=D9=88=D8=A8=D8=B1=
 2025 =D9=85</span></h2>

<h2 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin:2pt 0in 0.0001pt;line-height:107%;break-after:avoi=
d;font-size:13pt;font-family:&quot;Calibri Light&quot;,&quot;sans-serif&quo=
t;;color:rgb(46,116,181);font-weight:normal"><span lang=3D"AR-EG" style=3D"=
font-size:18pt;line-height:107%;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9 </span><span lan=
g=3D"AR-EG" style=3D"font-size:18pt;line-height:107%;font-family:&quot;Time=
s New Roman&quot;,&quot;serif&quot;">=E2=80=93</span><span lang=3D"AR-EG" s=
tyle=3D"font-size:18pt;line-height:107%;font-family:&quot;Times New Roman&q=
uot;,&quot;serif&quot;"> =D8=AC=D9=85=D9=87=D9=88=D8=B1=D9=8A=D8=A9 =D9=85=
=D8=B5=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 </span><span lang=
=3D"AR-EG" style=3D"font-size:18pt;line-height:107%;font-family:&quot;Times=
 New Roman&quot;,&quot;serif&quot;">=E2=80=93</span><span lang=3D"AR-EG" st=
yle=3D"font-size:18pt;line-height:107%;font-family:&quot;Times New Roman&qu=
ot;,&quot;serif&quot;"> =D8=A7=D9=84=D9=85=D9=82=D8=B1 =D8=A7=D9=84=D8=A7=
=D8=AF=D8=A7=D8=B1=D9=8A =D9=84=D9=84=D8=AF=D8=A7=D8=B1
=D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=
=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></h2>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-SA" style=3D"font-size:22pt;font-family:Arial,&quot;sans-serif&quot;=
">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D9=87=D9=86=D9=8A=D8=A9 =D9=85=D8=
=B9=D8=AA=D9=85=D8=AF=D8=A9 =E2=80=93 =D9=85=D9=88=D8=AB=D9=82=D8=A9 =D9=88=
=D8=A8=D8=A7=D8=B9=D8=AA=D9=85=D8=A7=D8=AF =D8=AF=D9=88=D9=84=D9=8A</span><=
/b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" s=
tyle=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
=C2=A0</span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-famil=
y:Arial,&quot;sans-serif&quot;">=D9=85=D8=B9=D8=AA=D8=B1=D9=81 =D8=A8=D9=87=
=D8=A7 =D9=81=D9=8A =D9=83=D8=A7=D9=81=D8=A9 =D8=A7=D9=84=D8=AF=D9=88=D9=84=
</span></b><span lang=3D"AR-SA" style=3D"font-size:12pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-SA" style=3D"font-size:22pt;font-family:Arial,&quot;sans-serif&quot;=
">=D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9=
 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AF=D8=A7=
=D8=B1=D9=8A=D8=A9 =E2=80=93=C2=A0</span></b><b><span dir=3D"LTR" style=3D"=
font-size:22pt">AHAD</span></b><span lang=3D"AR-SA" style=3D"font-size:12pt=
"></span></p>

<h2 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin:2pt 0in 0.0001pt;line-height:107%;break-after:avoi=
d;font-size:13pt;font-family:&quot;Calibri Light&quot;,&quot;sans-serif&quo=
t;;color:rgb(46,116,181);font-weight:normal"><span lang=3D"AR-SA" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D9=85=D8=B9 =D8=A7=D8=AA=D8=A7=D8=AD=D8=A9
=D8=A7=D9=84=D8=AF=D8=B1=D8=A7=D8=B3=D8=A9 =D8=A7=D9=88=D9=86 =D9=84=D8=A7=
=D9=8A=D9=86 =D8=A8=D8=B1=D8=B3=D9=88=D9=85 =D9=85=D8=AE=D9=81=D8=B6=D8=A9 =
=D9=81=D9=8A =D8=AD=D8=A7=D9=84 =D8=AA=D8=B9=D8=B0=D8=B1 =D8=A7=D9=84=D8=AD=
=D8=B6=D9=88=D8=B1</span><span dir=3D"LTR" style=3D"font-size:14pt;line-hei=
ght:107%"></span></h2>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D8=A7=D9=84=D8=A3=D9=87=D8=AF=D8=A7=D9=81</span><span=
 dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"fon=
t-size:16pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></h1=
>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D8=AA=D9=85=D9=83=D9=8A=D9=86 =D8=A7=D9=84=D9=82=D9=
=8A=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D9=84=D8=B5=D9=86=D8=A7=D8=B9=D9=8A=D8=
=A9 =D9=85=D9=86
=D8=AA=D8=B7=D8=A8=D9=8A=D9=82 =D9=85=D8=A8=D8=A7=D8=AF=D8=A6 =D8=A7=D9=84=
=D8=AD=D9=88=D9=83=D9=85=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span><span dir=3D"LTR" style=3D"font-size:16pt"><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span>.</span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D8=AA=D8=B9=D8=B2=D9=8A=D8=B2 =D8=A7=D9=84=D8=B4=D9=
=81=D8=A7=D9=81=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=B1=D9=82=D8=A7=D8=A8=D8=
=A9 =D8=AF=D8=A7=D8=AE=D9=84
=D8=A7=D9=84=D9=85=D9=86=D8=B4=D8=A2=D8=AA =D8=A7=D9=84=D8=B5=D9=86=D8=A7=
=D8=B9=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:16pt"><span dir=3D"LTR"></span><span d=
ir=3D"LTR"></span>.</span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D9=85=D9=88=D8=A7=D8=A1=D9=85=D8=A9 =D8=A7=D8=B3=D8=
=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D9=82=D9=
=8A=D8=A7=D8=AF=D8=A9 =D9=85=D8=B9 =D9=85=D8=AA=D8=B7=D9=84=D8=A8=D8=A7=D8=
=AA
=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=
=D8=AB=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:16pt"><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span>.</span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D8=B1=D9=81=D8=B9 =D9=83=D9=81=D8=A7=D8=A1=D8=A9 =D8=
=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1 =D9=88=D8=
=AA=D8=AD=D9=82=D9=8A=D9=82
=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9 =D8=A7=D9=84=D9=85=
=D8=A4=D8=B3=D8=B3=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span><span dir=3D"LTR" style=3D"font-size:16pt"><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span>.</span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D8=A7=D9=84=D9=81=D8=A6=D8=A9 =D8=A7=D9=84=D9=85=D8=
=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9</span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:16pt"><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span>:</span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D8=A7=D9=84=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=
=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=8A=D9=88=D9=86 =D9=88=D8=A3=D8=B9=D8=
=B6=D8=A7=D8=A1
=D9=85=D8=AC=D8=A7=D9=84=D8=B3 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9</=
span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" st=
yle=3D"font-size:16pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.<=
/span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=
=B5=D8=A7=D9=86=D8=B9 =D9=88=D8=A7=D9=84=D9=85=D9=86=D8=B4=D8=A2=D8=AA
=D8=A7=D9=84=D8=B5=D9=86=D8=A7=D8=B9=D9=8A=D8=A9</span><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:16pt"><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88 =D8=A7=D9=84=D8=
=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9
=D9=88=D8=A7=D9=84=D8=A7=D9=84=D8=AA=D8=B2=D8=A7=D9=85</span><span dir=3D"L=
TR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:16=
pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA =D8=
=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D9=
=82=D8=B7=D8=A7=D8=B9
=D8=A7=D9=84=D8=B5=D9=86=D8=A7=D8=B9=D9=8A</span><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:16pt"><span di=
r=3D"LTR"></span><span dir=3D"LTR"></span>.</span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D9=85=D8=AD=D8=A7=D9=88=D8=B1 =D8=A7=D9=84=D8=A8=D8=
=B1=D9=86=D8=A7=D9=85=D8=AC</span><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span><span dir=3D"LTR" style=3D"font-size:16pt"><span dir=3D"LTR"></spa=
n><span dir=3D"LTR"></span>:</span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D9=85=D8=AF=D8=AE=D9=84 =D8=A5=D9=84=D9=89 =D8=A7=D9=
=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=B5=D9=86=D8=A7=D8=B9=D9=
=8A=D8=A9
=D9=88=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=B1=D8=B4=
=D9=8A=D8=AF=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:16pt"><span dir=3D"LTR"></span><span d=
ir=3D"LTR"></span>.</span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=
=D8=A7=D8=AA =D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D9=81=D9=8A =D8=A8=
=D9=8A=D8=A6=D8=A9
=D8=B5=D9=86=D8=A7=D8=B9=D9=8A=D8=A9 =D9=85=D8=AA=D8=BA=D9=8A=D8=B1=D8=A9</=
span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" st=
yle=3D"font-size:16pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.<=
/span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D9=85=D8=A8=D8=A7=D8=AF=D8=A6 =D8=A7=D9=84=D8=AD=D9=
=88=D9=83=D9=85=D8=A9 =D9=88=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA=D9=
=87=D8=A7 =D9=81=D9=8A
=D8=A7=D9=84=D9=85=D8=B5=D8=A7=D9=86=D8=B9</span><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:16pt"><span di=
r=3D"LTR"></span><span dir=3D"LTR"></span>.</span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D8=A7=D9=84=D8=B4=D9=81=D8=A7=D9=81=D9=8A=D8=A9 =D9=
=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=
=B1 =D9=81=D9=8A
=D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=B9 =D8=A7=D9=84=D8=B5=D9=86=D8=A7=D8=B9=
=D9=8A</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:16pt"><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span>.</span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D8=A7=D9=84=D8=AA=D8=AC=D8=A7=D8=B1=D8=A8 =D8=A7=D9=
=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=B1=D8=A7=D8=A6=D8=AF=D8=
=A9 =D9=81=D9=8A
=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D8=B5=D8=A7=D9=86=D8=B9</=
span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" st=
yle=3D"font-size:16pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.<=
/span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:16pt">=D8=A2=D9=84=D9=8A=D8=A7=D8=AA =D8=AA=D8=B7=D9=88=D9=
=8A=D8=B1 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=A4=D8=
=B3=D8=B3=D9=8A
=D9=88=D8=B6=D9=85=D8=A7=D9=86 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AF=D8=A7=
=D9=85=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:16pt"><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span>.</span></h1>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:24pt;font-family:&quot;Times New Roman&quot=
;,&quot;serif&quot;">=D9=88=D8=A8=D9=87=D8=B0=D9=87 =D8=A7=D9=84=D9=85=D9=
=86=D8=A7=D8=B3=D8=A8=D8=A9
=D9=8A=D8=B3=D8=B9=D8=AF=D9=86=D8=A7 =D8=AF=D8=B9=D9=88=D8=AA=D9=83=D9=85 =
=D9=84=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =D9=88=D8=AA=D8=B9=D9=85=
=D9=8A=D9=85 =D8=AE=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =D8=B9=D9=84=D9=89 =D8=A7=
=D9=84=D9=85=D9=87=D8=AA=D9=85=D9=8A=D9=86 =D8=A8=D9=85=D9=80=D9=80=D9=88=
=D8=B6=D9=80=D9=88=D8=B9=C2=A0</span></b><b><span lang=3D"AR-EG" style=3D"f=
ont-size:24pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=
=D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=A7=D8=AD=D8=AA=
=D8=B1=D8=A7=D9=81=D9=8A=D8=A9=C2=A0</span></b><b><span lang=3D"AR-SA" styl=
e=3D"font-size:24pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=88=D8=A5=D9=81=D8=A7=D8=AF=D8=AA=D9=86=D8=A7 =D8=A8=D9=85=D9=86 =D8=
=AA=D9=82=D8=AA=D8=B1=D8=AD=D9=88=D9=86 =D8=AA=D9=88=D8=AC=D9=8A=D9=87 =D8=
=A7=D9=84=D8=AF=D8=B9=D9=88=D8=A9 =D9=84=D9=87=D9=85</span></b><span lang=
=3D"AR-SA" style=3D"font-size:24pt;font-family:&quot;Times New Roman&quot;,=
&quot;serif&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:24pt;font-family:&quot;Times New Roman&quot=
;,&quot;serif&quot;">=D9=84=D9=85=D8=B2=D9=8A=D8=AF =D9=85=D9=86
=D8=A7=D9=84=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA =D9=8A=D9=85=D9=83=
=D9=86=D9=83 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=85=D8=B9 =D8=A3=
 / =D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=
=A7=D8=AF =E2=80=93=D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=
=D9=8A=D8=A8 =E2=80=93 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=
=B1=D8=A8=D9=8A=D8=A9
=D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AF=D8=A7=
=D8=B1=D9=8A=D8=A9</span></b><span lang=3D"AR-SA" style=3D"font-size:24pt;f=
ont-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.25in 8pt 0in;direc=
tion:rtl;unicode-bidi:embed;line-height:107%;font-size:11pt;font-family:Cal=
ibri,&quot;sans-serif&quot;"><b><span lang=3D"AR-SA" style=3D"font-size:24p=
t;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =D8=AC=D9=88=D8=
=A7=D9=84 =E2=80=93 =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=A8 :</span></b><span=
 lang=3D"AR-SA" style=3D"font-size:24pt;font-family:&quot;Times New Roman&q=
uot;,&quot;serif&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font=
-size:24pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span=
 dir=3D"LTR"></span><span dir=3D"LTR"></span>00201069994399
-00201062992510 - 00201096841626</span></b><span lang=3D"AR-SA" style=3D"fo=
nt-size:24pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></s=
pan></p>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:28pt">=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 </span></h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:28pt">=C2=A0</span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A7=D8=
=AA =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9 (26 =E2=80=93 30=
 =D8=A3=D9=83=D8=AA=D9=88=D8=A8=D8=B1 2025=D9=85)</span><span dir=3D"LTR"><=
/span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span dir=3D"LTR" style=3D"font-family:&quot;Segoe UI Symbol=
&quot;,&quot;sans-serif&quot;">=F0=9F=94=B9</span><span dir=3D"LTR"> </span=
><strong><span lang=3D"AR-SA">=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D9=88=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 </span></strong><span dir=
=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=
=A9 =D8=A7=D9=84=D8=B0=D9=83=D9=8A=D8=A9 =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=
=A9 =D9=81=D8=B1=D9=82 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=B9=D8=A7=D9=84=D9=
=8A=D8=A9 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1</span><span dir=3D"LTR"></sp=
an></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=
=B7 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A =D8=
=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D9=85=D8=A4=D8=B4=D8=B1=D8=
=A7=D8=AA =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1</span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR"></span><span dir=3D"LTR"><span dir=3D"LTR"></span><spa=
n dir=3D"LTR"></span> KPI</span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=AA=D8=BA=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=
=D9=8A =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=
=D9=85=D9=8A</span><span dir=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span dir=3D"LTR" style=3D"font-family:&quot;Segoe UI Symbol=
&quot;,&quot;sans-serif&quot;">=F0=9F=94=B9</span><span dir=3D"LTR"> </span=
><strong><span lang=3D"AR-SA">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D8=
=A9 =D9=88=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span></strong><span d=
ir=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=D8=
=A8=D8=A9 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=
=AA=D9=82=D8=AF=D9=85=D8=A9 =D9=88=D9=81=D9=82</span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR"></span><span dir=3D"LTR"><span dir=3D"LTR"></span><spa=
n dir=3D"LTR"></span> IFRS</span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D8=AA=D8=AF=D9=82=D9=8A=D9=
=82 =D8=A7=D9=84=D8=AF=D8=A7=D8=AE=D9=84=D9=8A =D9=88=D9=85=D9=83=D8=A7=D9=
=81=D8=AD=D8=A9 =D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D9=8A=D8=A7=D9=84 =D8=A7=D9=
=84=D9=85=D8=A7=D9=84=D9=8A</span><span dir=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=
=B7 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D9=88=D8=A5=D8=B9=D8=AF=D8=A7=D8=
=AF =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B2=D9=86=D8=A7=D8=AA</span><span dir=
=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span dir=3D"LTR" style=3D"font-family:&quot;Segoe UI Symbol=
&quot;,&quot;sans-serif&quot;">=F0=9F=94=B9</span><span dir=3D"LTR"> </span=
><strong><span lang=3D"AR-SA">=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =
=D9=88=D8=A7=D9=84=D9=82=D8=A7=D9=86=D9=88=D9=86</span></strong><span dir=
=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=
=A9 =D9=88=D8=A7=D9=84=D8=B4=D9=81=D8=A7=D9=81=D9=8A=D8=A9 =D9=81=D9=8A =D8=
=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA</span><span dir=3D"LTR"></spa=
n></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=B9=D9=82=D9=88=D8=AF =D9=88=D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B2=
=D8=B9=D8=A7=D8=AA =D8=A7=D9=84=D9=82=D8=A7=D9=86=D9=88=D9=86=D9=8A=D8=A9</=
span><span dir=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=D8=
=A7=D9=84 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A =D9=88=D8=A7=D9=84=D8=
=A7=D9=84=D8=AA=D8=B2=D8=A7=D9=85 =D8=A8=D8=A7=D9=84=D9=82=D9=88=D8=A7=D9=
=86=D9=8A=D9=86 =D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9</span><span dir=
=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span dir=3D"LTR" style=3D"font-family:&quot;Segoe UI Symbol=
&quot;,&quot;sans-serif&quot;">=F0=9F=94=B9</span><span dir=3D"LTR"> </span=
><strong><span lang=3D"AR-SA">=D8=A7=D9=84=D9=85=D8=B4=D8=AA=D8=B1=D9=8A=D8=
=A7=D8=AA =D9=88=D8=A7=D9=84=D9=84=D9=88=D8=AC=D8=B3=D8=AA=D9=8A=D8=A7=D8=
=AA</span></strong><span dir=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=B3=
=D9=84=D8=A7=D8=B3=D9=84 =D8=A7=D9=84=D8=A5=D9=85=D8=AF=D8=A7=D8=AF =D9=88=
=D8=A7=D9=84=D8=AA=D9=88=D8=B1=D9=8A=D8=AF =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=
=D8=AB=D8=A9</span><span dir=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=
=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=
=AF=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=B4=D8=AA=D8=B1=D9=8A=D8=
=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9</span><span dir=
=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D9=85=D8=AE=D8=A7=D8=B2=D9=86 =D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=AA=
=D9=88=D8=AF=D8=B9=D8=A7=D8=AA =D9=88=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=
=D9=84=D9=85=D8=AE=D8=B2=D9=88=D9=86</span><span dir=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span dir=3D"LTR" style=3D"font-family:&quot;Segoe UI Symbol=
&quot;,&quot;sans-serif&quot;">=F0=9F=94=B9</span><span dir=3D"LTR"> </span=
><strong><span lang=3D"AR-SA">=D8=A7=D9=84=D8=A3=D9=85=D9=86 =D9=88=D8=A7=
=D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=A9 =D9=88=D8=A7=D9=84=D8=B5=D8=AD=D8=A9 =
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9</span></strong><span dir=3D"LTR"=
></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=
=A9 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9 =D9=88=D9=81=D9=82 =D9=85=D8=
=B9=D8=A7=D9=8A=D9=8A=D8=B1</span><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span><span dir=3D"LTR"><span dir=3D"LTR"></span><span dir=3D"LTR"></spa=
n> OSHA</span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1 =D9=88=D8=A7=D9=84=D8=A3=D8=B2=D9=85=
=D8=A7=D8=AA =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=86=D8=B4=D8=A2=D8=AA =D8=A7=
=D9=84=D8=B5=D9=86=D8=A7=D8=B9=D9=8A=D8=A9</span><span dir=3D"LTR"></span><=
/h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=
=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=85=D8=B9 =
=D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=AF =D8=A7=D9=84=D8=AE=D8=B7=D8=B1=D8=A9</=
span><span dir=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span dir=3D"LTR" style=3D"font-family:&quot;Segoe UI Symbol=
&quot;,&quot;sans-serif&quot;">=F0=9F=94=B9</span><span dir=3D"LTR"> </span=
><strong><span lang=3D"AR-SA">=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=
=D9=84=D8=B1=D9=82=D9=85=D9=8A =D9=88=D8=A7=D9=84=D8=AA=D9=82=D9=86=D9=8A=
=D8=A9</span></strong><span dir=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=88=D8=AA=D8=B7=
=D8=A8=D9=8A=D9=82=D8=A7=D8=AA=D9=87 =D9=81=D9=8A =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D8=A9</span><span dir=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=AD=D9=85=D8=A7=D9=8A=D8=A9 =D8=A7=
=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D8=A3=D9=85=
=D9=86 =D8=A7=D9=84=D8=B3=D9=8A=D8=A8=D8=B1=D8=A7=D9=86=D9=8A</span><span d=
ir=3D"LTR"></span></h1>

<h1 dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;=
margin-left:0in;font-size:24pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"><span lang=3D"AR-SA">=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=
=84=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=86=D8=A8=D8=A4=D9=8A=D8=A9 =D8=A8=D8=
=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85</span><span dir=3D"LTR"></span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span> Power
BI </span><span lang=3D"AR-SA">=D9=88</span><span dir=3D"LTR">Excel</span><=
/h1>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;direction:rtl;u=
nicode-bidi:embed;margin-right:0in;margin-left:0in;font-size:24pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR" style=
=3D"font-size:28pt">=C2=A0</span></h1></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKkH_86GeNSX0SM0%2BtKo8ejU7LjeDtDsz47t2aGMaMTbzw%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CADj1ZKkH_86GeNSX0SM0%2BtKo8ejU7LjeDtDsz47t2aGMaMTbzw%40mail=
.gmail.com</a>.<br />

--00000000000015276306416008bb--
