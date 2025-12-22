Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBJN5UPFAMGQEJHIU6VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id B75A6CD4C0D
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 07:01:11 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-64b9ee8a07esf2465739a12.2
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Dec 2025 22:01:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766383271; cv=pass;
        d=google.com; s=arc-20240605;
        b=EjaVr9JIoOFTmGz3/zCO30vdCGrXZ63/oWz3+tDaep7ghXcU2glejue6Jj3EvPev/u
         9RVzqmMxPbjWNMSigNDSWIZ8l4OZK47C294z9euI4KrmHTGrLLZ2mhXNkjjDdZY9EwYN
         i9nPOpH07U1f9Vxue6QgFxRctkwkusevhFl0xYfXqFMjMGnUNbDFpON6jiZafLuNsB1/
         IZXpAyJk3zNph8SjZGGH3gc67KFrVvHn0tQgL4vHazm7WDecqA8oSibzYjObg3/iH6kC
         oRYO+szgxJtBOY7HP/NiH9Ncr5JAk9sLMItODv7evK33xMjfesxNXKPeYLX/S8tKNgAN
         bbuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=ckWTb9lLkVNurC4qO+mId0OPweSxaVGFLsIVyI+baEA=;
        fh=fZb1jnWUza35Mb3CetBGl2S3B0l8Wx1xFBdxJfErSho=;
        b=ONGR1N5a8t2FB56Wbj7CEcPhI+wQtCGr/5xvdWK3UNXYsLSwUIBc4bP9w69BEldi6B
         DMcJGbo3sfiVnam2JFNKtbEsNgbjJUrQi5D8PriAfP0eE9C/y/CJ9lTOUYxde19EVNZk
         PZFPHyuN5M/sFUWS5zFNiN7nu+dU6/tCOBdsfINv1dsP7eD/GaRQThIQvoBDlzUr6t3s
         fh7r+ycIvD3jJgdTfLxKOBFujqInRbZtFYbKT65gmqGdagX6obX8aiNEmJ4Zr9axA3PN
         +DIgZ/zmsPDTDzRERIx+ZPbro57pZVuLwD+dunPCksf3yZXWK3EtKKt8YF9Jq64hpDRi
         fQSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q1o3dUKJ;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766383271; x=1766988071; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ckWTb9lLkVNurC4qO+mId0OPweSxaVGFLsIVyI+baEA=;
        b=ESlUtynqAuR+Sme3Zyyv2ZkMwISP8mHD7v/ZzS2UC4/95GqgzyDlQxXvJNxgvvzaqo
         A5CdeujNp95BC+6QrsNKXE2W/w3n5CpBJk/n2aXx2iUzb6oYyBLPSi0fo7s74bZJgoTM
         EgeS3GdU99tV3mGjgOocWe3slCywGUCcgzcwYQ23Mtq/36rJVLUBElC75Pnw/BFDTz9P
         Vt0hRs/56SY0iI2pgiCZi/gTaghxHaDwB/FsAFeD7D+JmJ9By+jO2jszZAJisSv5ChHX
         Rp9C+2p0pB1C7FDAAwKVVUYZUq/feWIx7LVqvhTiqpwGPZATJZJfJzhpPOMieYB/Cv5u
         29tA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1766383271; x=1766988071; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=ckWTb9lLkVNurC4qO+mId0OPweSxaVGFLsIVyI+baEA=;
        b=ZatjR7iKmmO8ItsknuG3hDc+E3WmqSIR6Npi1R8ZBCOWz3rFyxHjd3wZGBBekhwKk5
         E96IxJAY7fqagHwX9Ui8ERY5Zh353wSIpMi53xJLhBUQuWYXZoFlE68UqMlgnu1YZ59n
         pKR/Y8oCmM2p1Xi1+2WqUWU4kvNgLzazuzjeFqDZEG2gZU8igi/rAbIrfmlBjNW7ggAF
         CyuKkQDK8YWTpyTfZhlEizM8Yv2RoEirFo+Tm9zJoGvGK3uOlG9VKAFPF1hX7qEgmHSB
         2lqVjne/C/rMpwZD5e4pKw5oYtjNNXpPG8vP42PJZIQVp3XWnvaOsi3mzpAtinMwO4qv
         pvCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766383271; x=1766988071;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ckWTb9lLkVNurC4qO+mId0OPweSxaVGFLsIVyI+baEA=;
        b=sAH/Nb+XAicEIOqOr1xfi695U9Mi1Q7wiKoOPjDxb91BmX4M7+wKnbBhNTO+2an63K
         vztmbO5AzD2lphY5C0GkyBavJrUO7L+9rW1tCvXr7lfZLbw+OamNjL34OXfiZYF/Lg2Q
         iW23B1c2kSxhx0FNZx5cwgEbfaP9MlcJUnNEiEWOC4riOaLcfLhUPSTq/notPvDyJUnC
         L4F2YVxn4VEZyrsHhiAX6ruLf4/dNgkCdOjFwrlWykFTqK16M7KGdDVbFXt3YEZwVl7H
         tv5SK7HiQWHF/ptYf6EfqQ4+rya7TJ3bq78E7YjoAtdkXvN40gvp9zqyJggGMwhYMyEv
         n7cQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU0OClOXDJICA3xOdAdLa8sx/GNfscFzYfwpP35olj4iS9u2zD4hTSf5seyqEzt0Hp8M8MEMw==@lfdr.de
X-Gm-Message-State: AOJu0YxrYWMX6Ma/TRgJ+5jSoCojWeWlI3qhQokU7I+uI7/V7Y4/AvUb
	UrEFGrjB0N9jW/QF4+WZhIVhmAG7s6yQJjGBTKZjsPFsFTZbSwJd3ccP
X-Google-Smtp-Source: AGHT+IFKzs+i/XZQmBz34+0UNcw1MplzPQNhe3B6cl20gVYbxrDI4YmjUrbLDNUinv8BIbCkKOzhrw==
X-Received: by 2002:a05:6402:35c6:b0:64d:2769:8460 with SMTP id 4fb4d7f45d1cf-64d276986c7mr4145986a12.6.1766383270613;
        Sun, 21 Dec 2025 22:01:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbHQ3A1e5ChiK7At0Wz7n/u7jdDbyeyhNxbUlriKg62Bw=="
Received: by 2002:a05:6402:4610:20b0:649:784c:cac1 with SMTP id
 4fb4d7f45d1cf-6499a433fe7ls7405345a12.2.-pod-prod-09-eu; Sun, 21 Dec 2025
 22:01:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUg5OdzJ/lVMyquk0G3b5ZQW67ZH+R8ScLL75KJ2Xyklbw3VqUtT4ehO5FzrS3gRA/cOA2euteomcY=@googlegroups.com
X-Received: by 2002:a05:6402:5cd:b0:64b:7885:c971 with SMTP id 4fb4d7f45d1cf-64b8eddf9f8mr9151704a12.20.1766383267651;
        Sun, 21 Dec 2025 22:01:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766383267; cv=none;
        d=google.com; s=arc-20240605;
        b=Sf7bHFHOt6KK64yaoTUytk3iXpVv3Kz/sNX9bF+U8fRATn/6ZleWSTayMtUMwVInXF
         dSSB/yA1T0Lb1MrXc0Fw4OWvvL5quF+00kBXGecVVgzTPXJJRhDMGoc0o4DIfacx1GiZ
         fmN1akVRHhvXoAVMaZ5UZwwNq7mT/KK4F/qsBq9d5rsams8nao0V7P81Yk0csWGmXMqt
         P6/y3jthtpRIsDynkDz0MPHeVIuheJHxSJf37UZwV952qSfL0Y0RJ8rJqcICSWM1gJqF
         XLgDB0x3e8IofBACZdIQte3JTMi9UaoKc63Rb4A+E1eZKIu1VcQ/XsOv0j/tinxivdb6
         6/4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=mCSQnOmSpVmr4GNVCQQx3cay7lnX0tPEG6gJHmLb6mg=;
        fh=lnoyQbNC0KV8oJJJ+b0SJPGcjZFhvyKrk1OxInaAjEs=;
        b=KhNhIq031ezMKoROTZrSLqQQeAjh9mhyvk1/HHlivacFWUv/sl/Zp6ajC5H1SlgRms
         tAgbKY0JZIHtSRkys9lmwj60e5j0ZFqksNeIjuZTyQKQ70BteAqeQNdkcUFQbEbw8GjL
         iaBLpM3jVpl0d0iY0ASEQIkJkaENwT+7kL8WgCggfHxNTDvaqh04Jfp+XigDmKbG6qtS
         1rhPT+Gw8sjMjIvd9ZOg6DrCqKMch+z4+enKv3fVE6DkoVIvROO9kmY/2TOHNJ5ikNL/
         cHXk4+/DylTODkWL0a1h4mnS5FVc/XQg5/rqtQ7tWIjRl4Z/cM4LlZfkV0PBtM0eLqy8
         Qkbw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q1o3dUKJ;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64b90412a75si136231a12.0.2025.12.21.22.01.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Dec 2025 22:01:07 -0800 (PST)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id 4fb4d7f45d1cf-64b7a38f07eso4359435a12.0
        for <kasan-dev@googlegroups.com>; Sun, 21 Dec 2025 22:01:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWler5r/JCq2DrHOI9xvmAi6KP6rQcp8nyGxabacZAoH7adRWEdp3xdrxNMXLXXgCkWF2oiBY0NTGQ=@googlegroups.com
X-Gm-Gg: AY/fxX6Nmw0JJ1ywhPzPf0sxJ+UJvCYNTGq2y9rc7NQ4+pFQ49lsvuy4XcNcIRgxGPk
	aZziyGrhhE2V/zsXSDjCTltwlpXWikqqQpbVJFiR8BMzdmMFqJF9FiUICaeQjfQ3HpCjT63zEMh
	y1iKQWGQhYNwsL21VgOEMJXPB381l/5dsF1efGwuoH8wouJ2Bjq9TM8WBiozc6fY7t4wcGZGk1A
	5PtEx9x3SsguDn4VN2Oe6RVRTrcgVa+VG4Ydu0uIUOvtyrQqD1bki4aS8jOF1Xcb+mnYX2+Tm+T
	JkM=
X-Received: by 2002:a17:907:72cd:b0:b7a:72bd:ac5d with SMTP id
 a640c23a62f3a-b8036ebbba7mr1011557166b.13.1766383266221; Sun, 21 Dec 2025
 22:01:06 -0800 (PST)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Mon, 22 Dec 2025 08:00:00 +0200
X-Gm-Features: AQt7F2q9KhkLdCtM67y2wfXvdNiJRsNTCZf4yCf1dSzOzXdBhmuJrCW3tRImWU8
Message-ID: <CADj1ZKnVpBdrtYDb37omqpYX=D0uYLGJiiAOaZvkv8Y7LUsMBQ@mail.gmail.com>
Subject: =?UTF-8?B?2KfZhNio2YPYr9isINin2YTYtNin2YXZhCDZgdmKINin2YTYrdmI2YPZhdipICgg2YrZhg==?=
	=?UTF-8?B?2KfZitixIDIwMjYgLSDCoDggwqDCoNio2YDZgNix2KfZhdiswqDCoNiq2K/YsdmK2KjZitipKQ==?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000001ed785064684270a"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Q1o3dUKJ;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::530
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

--0000000000001ed785064684270a
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2YrYs9ix2ZEg2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE2KXY
r9in2LHZitipINiq2YLYr9mK2YUg2KfZhNio2YPYr9isINin2YTZhdmH2YbZiiDYp9mE2YXYqtiu
2LXYtSDZgdmKINin2YTYrdmI2YPZhdipDQrYp9mE2YXYpNiz2LPZitip2Iwg2YjYp9mE2LDZiiDZ
iti52KrZhdivINi52YTZiSDYp9mE2YXYqNin2K/YpiDYp9mE2K/ZiNmE2YrYqSDZhNmE2K3ZiNmD
2YXYqSDZiNij2YHYttmEINin2YTZhdmF2KfYsdiz2KfYqiDZiNin2YTZhdi52KfZitmK2LENCtin
2YTZhdmC2KfYsdmG2Kkg2KfZhNmF2LnYqtmF2K/YqSDYudin2YTZhdmK2YvYp9iMINmF2Lkg2YXY
sdin2LnYp9ipINin2K7YqtmE2KfZgSDYp9mE2KPYt9ixINin2YTYqtmG2LjZitmF2YrYqSDZiNin
2YTYqti02LHZiti52YrYqSDYqNmK2YYNCtin2YTYr9mI2YTYjCDYqNmF2Kcg2YrYqtmK2K0g2KrY
t9io2YrZgtmHINmB2Yog2YXYrtiq2YTZgSDYp9mE2YLYt9in2LnYp9iqINmI2LnZhNmJINin2YTZ
hdiz2KrZiNmK2YrZhiDYp9mE2LnYsdio2Yog2YjYp9mE2K/ZiNmE2YrYjA0K2YjZitmH2K/ZgSDY
pdmE2Ykg2KrYudiy2YrYsiDZhdio2KfYr9imINin2YTYtNmB2KfZgdmK2Kkg2YjYp9mE2YXYs9in
2KHZhNip2Iwg2YjYsdmB2Lkg2YPZgdin2KHYqSDYp9mE2KPYr9in2KEg2KfZhNmF2KTYs9iz2YrY
jCDZiNiv2LnZhQ0K2KzZiNiv2Kkg2KfYqtiu2KfYsCDYp9mE2YLYsdin2LEg2YjZgdmCINin2YTY
o9i32LEg2KfZhNiv2YjZhNmK2Kkg2KfZhNmF2LnYqtmF2K/YqS4NCg0K8J+Pm++4jyAg2KfZhNio
2YPYr9isINin2YTYtNin2YXZhCDZgdmKINin2YTYrdmI2YPZhdipICgg2YrZhtin2YrYsSAyMDI2
IC0gIDggICDYqNmA2YDYsdin2YXYrCAgINiq2K/YsdmK2KjZitipKQ0KDQoxLiAq2YXYqNin2K/Y
piDYp9mE2K3ZiNmD2YXYqSDYp9mE2YXYpNiz2LPZitipKg0KDQrZhdit2KfZiNixINin2YTYqNix
2YbYp9mF2Kw6DQoNCsKnICAgICAgINmF2YHZh9mI2YUg2KfZhNit2YjZg9mF2Kkg2YjYo9mH2YXZ
itiq2YfYpw0KDQrCpyAgICAgICDYo9mH2K/Yp9mBINin2YTYrdmI2YPZhdipINmI2YHZiNin2KbY
r9mH2KcNCg0KwqcgICAgICAg2KPYt9ix2KfZgSDYp9mE2K3ZiNmD2YXYqSAo2KfZhNmF2YTYp9mD
IOKAkyDZhdis2YTYsyDYp9mE2KXYr9in2LHYqSDigJMg2KfZhNil2K/Yp9ix2Kkg2KfZhNiq2YbZ
gdmK2LDZitipKQ0KDQrCpyAgICAgICDZhdio2KfYr9imINin2YTYrdmI2YPZhdipICjYp9mE2LTZ
gdin2YHZitip2Iwg2KfZhNmF2LPYp9ih2YTYqdiMINin2YTYudiv2KfZhNip2Iwg2KfZhNin2LPY
qtmC2YTYp9mE2YrYqSkNCg0KwqcgICAgICAg2YbZhdin2LDYrCDYp9mE2K3ZiNmD2YXYqSDYp9mE
2K/ZiNmE2YrYqQ0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQoNCjIuICrYrdmI2YPZ
hdipINin2YTYtNix2YPYp9iqICgqKkNvcnBvcmF0ZSBHb3Zlcm5hbmNlKiopKg0KDQrZhdit2KfZ
iNixINin2YTYqNix2YbYp9mF2Kw6DQoNCsKnICAgICAgINin2YTYpdi32KfYsSDYp9mE2YbYuNin
2YXZiiDZhNit2YjZg9mF2Kkg2KfZhNi02LHZg9in2KoNCg0KwqcgICAgICAg2YXYs9ik2YjZhNmK
2KfYqiDZhdis2YTYsyDYp9mE2KXYr9in2LHYqQ0KDQrCpyAgICAgICDZhNis2KfZhiDZhdis2YTY
syDYp9mE2KXYr9in2LHYqSAo2KfZhNmF2LHYp9is2LnYqdiMINin2YTYqtix2LTZitit2KfYqtiM
INin2YTZhdmD2KfZgdii2KopDQoNCsKnICAgICAgINit2YLZiNmCINin2YTZhdiz2KfZh9mF2YrZ
hiDZiNij2LXYrdin2Kgg2KfZhNmF2LXYp9mE2K0NCg0KwqcgICAgICAg2KfZhNil2YHYtdin2K0g
2YjYp9mE2LTZgdin2YHZitipDQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCg0KMy4g
Ktit2YjZg9mF2Kkg2KfZhNmC2LfYp9i5INin2YTYrdmD2YjZhdmKKg0KDQrZhdit2KfZiNixINin
2YTYqNix2YbYp9mF2Kw6DQoNCsKnICAgICAgINmF2YHZh9mI2YUg2KfZhNit2YjZg9mF2Kkg2YHZ
iiDYp9mE2KzZh9in2Kog2KfZhNit2YPZiNmF2YrYqQ0KDQrCpyAgICAgICDYrdmI2YPZhdipINin
2KrYrtin2LAg2KfZhNmC2LHYp9ixDQoNCsKnICAgICAgINin2YTZhtiy2KfZh9ipINmI2YXZg9in
2YHYrdipINin2YTZgdiz2KfYrw0KDQrCpyAgICAgICDZgtmK2KfYsyDYp9mE2KPYr9in2KEg2KfZ
hNit2YPZiNmF2YoNCg0KwqcgICAgICAg2KfZhNin2YXYqtir2KfZhCDZiNin2YTYsdmC2KfYqNip
INin2YTYrdmD2YjZhdmK2KkNCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQo0LiAq
2K3ZiNmD2YXYqSDYp9mE2YXYrtin2LfYsSDZiNin2YTYp9mE2KrYstin2YUgKCoqR1JDKiopKg0K
DQrZhdit2KfZiNixINin2YTYqNix2YbYp9mF2Kw6DQoNCsKnICAgICAgINmF2YHZh9mI2YUgR1JD
DQoNCsKnICAgICAgINil2K/Yp9ix2Kkg2KfZhNmF2K7Yp9i32LEg2KfZhNmF2KTYs9iz2YrYqSBF
Uk0NCg0KwqcgICAgICAg2KfZhNin2YXYqtir2KfZhCDZhNmE2KPZhti42YXYqSDZiNin2YTZhNmI
2KfYptitDQoNCsKnICAgICAgINiv2YjYsSDYp9mE2K3ZiNmD2YXYqSDZgdmKINiq2YLZhNmK2YQg
2KfZhNmF2K7Yp9i32LENCg0KwqcgICAgICAg2LHYqNi3INin2YTYrdmI2YPZhdipINio2KfZhNin
2LPYqtiv2KfZhdipDQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCg0KNS4gKtit2YjZ
g9mF2Kkg2KfZhNmF2LHYp9is2LnYqSDYp9mE2K/Yp9iu2YTZitipKg0KDQrZhdit2KfZiNixINin
2YTYqNix2YbYp9mF2Kw6DQoNCsKnICAgICAgINiv2YjYsSDYp9mE2YXYsdin2KzYudipINin2YTY
r9in2K7ZhNmK2Kkg2YHZiiDYp9mE2K3ZiNmD2YXYqQ0KDQrCpyAgICAgICDYp9mE2LnZhNin2YLY
qSDYqNmK2YYg2KfZhNmF2LHYp9is2LnYqSDZiNmF2KzZhNizINin2YTYpdiv2KfYsdipDQoNCsKn
ICAgICAgINin2LPYqtmC2YTYp9mE2YrYqSDYp9mE2YXYsdin2KzYuSDYp9mE2K/Yp9iu2YTZig0K
DQrCpyAgICAgICDYqtmC2KfYsdmK2LEg2KfZhNmF2LHYp9is2LnYqQ0KDQrCpyAgICAgICDYp9mE
2YXYudin2YrZitixINin2YTYr9mI2YTZitipINmE2YTZhdix2KfYrNi52Kkg2KfZhNiv2KfYrtmE
2YrYqQ0KDQoNCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQo2LiAq2K3ZiNmD2YXY
qSDYp9mE2YXZiNin2LHYryDYp9mE2KjYtNix2YrYqSoNCg0K2YXYrdin2YjYsSDYp9mE2KjYsdmG
2KfZhdisOg0KDQrCpyAgICAgICDYr9mI2LEg2KfZhNit2YjZg9mF2Kkg2YHZiiDYpdiv2KfYsdip
INin2YTZhdmI2KfYsdivINin2YTYqNi02LHZitipDQoNCsKnICAgICAgINin2YTYudiv2KfZhNip
INmI2KrZg9in2YHYpCDYp9mE2YHYsdi1DQoNCsKnICAgICAgINit2YjZg9mF2Kkg2KfZhNiq2YjY
uNmK2YEg2YjYp9mE2KrYsdmC2YrYp9iqDQoNCsKnICAgICAgINil2K/Yp9ix2Kkg2KfZhNij2K/Y
p9ihINmI2KfZhNmF2LPYp9ih2YTYqQ0KDQrCpyAgICAgICDYo9iu2YTYp9mC2YrYp9iqINin2YTY
udmF2YQg2YjYp9mE2LPZhNmI2YMg2KfZhNmI2LjZitmB2YoNCi0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLQ0KDQo3LiAq2K3ZiNmD2YXYqSDYqtmC2YbZitipINin2YTZhdi52YTZiNmF2KfY
qiDZiNin2YTYqtit2YjZhCDYp9mE2LHZgtmF2YoqDQoNCtmF2K3Yp9mI2LEg2KfZhNio2LHZhtin
2YXYrDoNCg0KwqcgICAgICAg2YXZgdmH2YjZhSDYrdmI2YPZhdipINiq2YLZhtmK2Kkg2KfZhNmF
2LnZhNmI2YXYp9iqDQoNCsKnICAgICAgINmF2YjYp9ih2YXYqSDYp9mE2KrZgtmG2YrYqSDZhdi5
INij2YfYr9in2YEg2KfZhNmF2KTYs9iz2KkNCg0KwqcgICAgICAg2KXYr9in2LHYqSDYo9mF2YYg
2KfZhNmF2LnZhNmI2YXYp9iqDQoNCsKnICAgICAgINil2K/Yp9ix2Kkg2KfZhNio2YrYp9mG2KfY
qiDZiNin2YTYrti12YjYtdmK2KkNCg0KwqcgICAgICAg2KPYt9ixIENPQklUINmISVQgR292ZXJu
YW5jZQ0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQoNCjguICrYrdmI2YPZhdipINin
2YTYp9iz2KrYr9in2YXYqSDZiNin2YTZhdiz2KTZiNmE2YrYqSDYp9mE2KfYrNiq2YXYp9i52YrY
qSoNCg0K2YXYrdin2YjYsSDYp9mE2KjYsdmG2KfZhdisOg0KDQrCpyAgICAgICDZhdmB2YfZiNmF
INin2YTYrdmI2YPZhdipINin2YTZhdiz2KrYr9in2YXYqQ0KDQrCpyAgICAgICBFU0cgKNin2YTY
qNmK2KbYqSDigJMg2KfZhNmF2KzYqtmF2Lkg4oCTINin2YTYrdmI2YPZhdipKQ0KDQrCpyAgICAg
ICDYp9mE2YXYs9ik2YjZhNmK2Kkg2KfZhNin2KzYqtmF2KfYudmK2Kkg2YTZhNmF2KTYs9iz2KfY
qg0KDQrCpyAgICAgICDYp9mE2KrZgtin2LHZitixINi62YrYsSDYp9mE2YXYp9mE2YrYqQ0KDQrC
pyAgICAgICDYp9mE2K3ZiNmD2YXYqSDZiNiv2LnZhSDYp9mE2KfYs9iq2K/Yp9mF2Kkg2KfZhNmF
2KTYs9iz2YrYqQ0KDQoNCg0K2KfZhNmF2YXZitiy2KfYqjoNCg0KwqcgICAgICAg4pyUINi02YfY
p9iv2KfYqiDZhdi52KrZhdiv2KkNCg0KwqcgICAgICAg4pyUINiq2YbZgdmK2LAgIti52YYg2KjZ
j9i52K8iIOKAkyDYo9mI2YLYp9iqINmF2LHZhtipDQoNCsKnICAgICAgIOKclCDYqti32KjZitmC
2KfYqiDYudmF2YTZitipICsg2YbZhdin2LDYrCDYrNin2YfYstipDQoNCsKnICAgICAgIOKclCDY
r9i52YUg2YHZhtmKINmI2YXYqtin2KjYudipINio2LnYryDYp9mE2KrYr9ix2YrYqA0KDQrCpyAg
ICAgICDinJQgOCDYqNix2KfZhdisINiq2K/YsdmK2KjZitipINmF2KrZg9in2YXZhNipDQoNCsKn
ICAgICAgIOKclCDZiti12YTYrSDZg9mF2LPYp9ixINiq2K/YsdmK2KjZiiDYo9mIINiv2KjZhNmI
2YUg2YXYtdi62LEg2YHZiiDYp9mE2K3ZiNmD2YXYqQ0KDQrCpyAgICAgICDinJQg2YXZhtin2LPY
qCDZhNmE2YXZiNi42YHZitmGIOKAkyDYp9mE2YfZitim2KfYqiDigJMg2KfZhNmF2K/Ysdio2YrZ
hiDigJMg2KfZhNil2K/Yp9ix2YrZitmGINmE2YTZgti32KfYuSDYp9mE2K3Zg9mI2YXZig0K2YjY
p9mE2K7Yp9i1DQoNCg0KDQrYqNmK2KfZhtin2Kog2KfZhNmA2YDZgNiq2YjYp9i12YQg2YTZhNiq
2LPYrNmK2YQg2YjYp9mE2KfYs9iq2YHYs9in2LE6DQoNCirYoy8g2LPYp9ix2Kkg2LnYqNivINin
2YTYrNmI2KfYryDigJMg2YXYr9mK2LEg2KfZhNiq2K/YsdmK2KgqDQrYp9mE2YfYp9iq2YE6DQoN
Cg0KKjAwMjAxMDY5OTk0Mzk5IDAwMjAxMDYyOTkyNTEwIDAwMjAxMDk2ODQxNjI2Kg0K2KfZhNis
2YfYqTog2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE2KXYr9in
2LHZitipDQoNCi0tIApZb3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBz
dWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBzICJrYXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1
YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0
LCBzZW5kIGFuIGVtYWlsIHRvIGthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29t
LgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiB2aXNpdCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29t
L2QvbXNnaWQva2FzYW4tZGV2L0NBRGoxWktuVnBCZHJ0WURiMzdvbXFwWVglM0REMHVZTEdKaWlB
T2Fadmt2OFk3TFVzTUJRJTQwbWFpbC5nbWFpbC5jb20uCg==
--0000000000001ed785064684270a
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:jus=
tify;margin:0cm 0cm 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D=
"font-size:16pt;line-height:107%;font-family:Arial,sans-serif">=D9=8A=D8=B3=
=D8=B1=D9=91 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=
=D9=8A=D8=A9
=D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=
=D8=B1=D9=8A=D8=A9 =D8=AA=D9=82=D8=AF=D9=8A=D9=85 =D8=A7=D9=84=D8=A8=D9=83=
=D8=AF=D8=AC =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D8=A7=D9=84=D9=85=D8=AA=
=D8=AE=D8=B5=D8=B5 =D9=81=D9=8A =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =
=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=D8=A9=D8=8C</span><span dir=3D"L=
TR"></span><span dir=3D"LTR"></span><span lang=3D"AR-SA" dir=3D"LTR" style=
=3D"font-size:16pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span> </span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-heigh=
t:107%;font-family:Arial,sans-serif">=D9=88=D8=A7=D9=84=D8=B0=D9=8A =D9=8A=
=D8=B9=D8=AA=D9=85=D8=AF =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=D8=A8=D8=A7=
=D8=AF=D8=A6 =D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9 =D9=84=D9=84=D8=AD=
=D9=88=D9=83=D9=85=D8=A9 =D9=88=D8=A3=D9=81=D8=B6=D9=84 =D8=A7=D9=84=D9=85=
=D9=85=D8=A7=D8=B1=D8=B3=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D9=85=D8=B9=D8=A7=
=D9=8A=D9=8A=D8=B1
=D8=A7=D9=84=D9=85=D9=82=D8=A7=D8=B1=D9=86=D8=A9 =D8=A7=D9=84=D9=85=D8=B9=
=D8=AA=D9=85=D8=AF=D8=A9 =D8=B9=D8=A7=D9=84=D9=85=D9=8A=D9=8B=D8=A7=D8=8C =
=D9=85=D8=B9 =D9=85=D8=B1=D8=A7=D8=B9=D8=A7=D8=A9 =D8=A7=D8=AE=D8=AA=D9=84=
=D8=A7=D9=81 =D8=A7=D9=84=D8=A3=D8=B7=D8=B1 =D8=A7=D9=84=D8=AA=D9=86=D8=B8=
=D9=8A=D9=85=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=B4=D8=B1=D9=8A=D8=B9=
=D9=8A=D8=A9 =D8=A8=D9=8A=D9=86
=D8=A7=D9=84=D8=AF=D9=88=D9=84=D8=8C =D8=A8=D9=85=D8=A7 =D9=8A=D8=AA=D9=8A=
=D8=AD =D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D9=87 =D9=81=D9=8A =D9=85=D8=AE=D8=AA=
=D9=84=D9=81 =D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=B9=D8=A7=D8=AA =D9=88=D8=B9=
=D9=84=D9=89 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=88=D9=8A=D9=8A=D9=86 =D8=A7=
=D9=84=D8=B9=D8=B1=D8=A8=D9=8A =D9=88=D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=
=D8=8C =D9=88=D9=8A=D9=87=D8=AF=D9=81
=D8=A5=D9=84=D9=89 =D8=AA=D8=B9=D8=B2=D9=8A=D8=B2 =D9=85=D8=A8=D8=A7=D8=AF=
=D8=A6 =D8=A7=D9=84=D8=B4=D9=81=D8=A7=D9=81=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=
=D9=85=D8=B3=D8=A7=D8=A1=D9=84=D8=A9=D8=8C =D9=88=D8=B1=D9=81=D8=B9 =D9=83=
=D9=81=D8=A7=D8=A1=D8=A9 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=D9=84=
=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=D8=8C =D9=88=D8=AF=D8=B9=D9=85 =D8=AC=D9=88=
=D8=AF=D8=A9 =D8=A7=D8=AA=D8=AE=D8=A7=D8=B0
=D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1 =D9=88=D9=81=D9=82 =D8=A7=D9=84=D8=A3=
=D8=B7=D8=B1 =D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=
=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:107%"><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0cm 0cm 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:24pt;line-height:107%;font-family:&quot;Segoe UI Symbol&quot;,san=
s-serif">=F0=9F=8F=9B=EF=B8=8F</span><span lang=3D"AR-SA" style=3D"font-siz=
e:24pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-ser=
if">=C2=A0 =D8=A7=D9=84=D8=A8=D9=83=D8=AF=D8=AC =D8=A7=D9=84=D8=B4=D8=A7=D9=
=85=D9=84 =D9=81=D9=8A =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 ( =D9=8A=
=D9=86=D8=A7=D9=8A=D8=B1 2026 - =C2=A08 =C2=A0=C2=A0=D8=A8=D9=80=D9=80=D8=
=B1=D8=A7=D9=85=D8=AC
=C2=A0=C2=A0=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9)</span></p>

<p class=3D"gmail-MsoListParagraph" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;line-height:115%;margin:0cm 36pt 8pt 0cm;direction:rtl;uni=
code-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=
=3D"font-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">1.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;font-size-adjust:none;font-=
kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt=
;line-height:normal;font-family:&quot;Times New Roman&quot;">
</span></span><span dir=3D"RTL"></span><u><span lang=3D"AR-SA" style=3D"fon=
t-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,san=
s-serif">=D9=85=D8=A8=D8=A7=D8=AF=D8=A6 =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=
=85=D8=A9 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=D8=A9</span></u></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:115%;margin:0cm 0cm=
 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sa=
ns-serif"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:115%;fon=
t-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D9=85=D8=AD=D8=A7=D9=
=88=D8=B1 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 68pt 0.0001pt 0cm;line-height:115%;direction:rtl;unicode-bidi:embed;font-=
size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D9=85=D9=81=D9=87=
=D9=88=D9=85 =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=88=D8=A3=D9=87=
=D9=85=D9=8A=D8=AA=D9=87=D8=A7</span><span lang=3D"AR-SA" style=3D"font-siz=
e:18pt;line-height:115%;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:115%;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;li=
ne-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;f=
ont-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-st=
retch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New R=
oman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=A3=D9=87=D8=AF=
=D8=A7=D9=81 =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=88=D9=81=D9=88=
=D8=A7=D8=A6=D8=AF=D9=87=D8=A7</span><span lang=3D"AR-SA" style=3D"font-siz=
e:18pt;line-height:115%;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:115%;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;li=
ne-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;f=
ont-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-st=
retch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New R=
oman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=A3=D8=B7=D8=B1=
=D8=A7=D9=81 =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 (=D8=A7=D9=84=D9=85=
=D9=84=D8=A7=D9=83 =E2=80=93 =D9=85=D8=AC=D9=84=D8=B3 =D8=A7=D9=84=D8=A5=D8=
=AF=D8=A7=D8=B1=D8=A9 =E2=80=93 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=8A=D8=A9)</span><span lang=3D=
"AR-SA" style=3D"font-size:18pt;line-height:115%;font-family:Arial,sans-ser=
if"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:115%;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;li=
ne-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;f=
ont-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-st=
retch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New R=
oman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D9=85=D8=A8=D8=A7=
=D8=AF=D8=A6 =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 (=D8=A7=D9=84=D8=B4=
=D9=81=D8=A7=D9=81=D9=8A=D8=A9=D8=8C =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=A1=
=D9=84=D8=A9=D8=8C =D8=A7=D9=84=D8=B9=D8=AF=D8=A7=D9=84=D8=A9=D8=8C =D8=A7=
=D9=84=D8=A7=D8=B3=D8=AA=D9=82=D9=84=D8=A7=D9=84=D9=8A=D8=A9)</span><span l=
ang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;font-family:Arial,sa=
ns-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 68pt 8pt 0cm;line-height:115%;direction:rtl;unicode-bidi:embed;font-size:1=
1pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-heig=
ht:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;font-siz=
e-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stretch:n=
ormal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&qu=
ot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D9=86=D9=85=D8=A7=
=D8=B0=D8=AC =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=AF=
=D9=88=D9=84=D9=8A=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:18pt=
;line-height:115%;font-family:Arial,sans-serif"></span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;line-height:115%;margin:0cm 0cm 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"gmail-MsoListParagraph" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;line-height:115%;margin:0cm 36pt 8pt 0cm;direction:rtl;uni=
code-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=
=3D"font-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">2.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;font-size-adjust:none;font-=
kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt=
;line-height:normal;font-family:&quot;Times New Roman&quot;">
</span></span><span dir=3D"RTL"></span><u><span lang=3D"AR-SA" style=3D"fon=
t-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,san=
s-serif">=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=
=A7=D8=AA (</span></u><u><span dir=3D"LTR" style=3D"font-size:26pt;line-hei=
ght:115%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif">Corporate G=
overnance</span></u><span dir=3D"RTL"></span><span dir=3D"RTL"></span><u><s=
pan lang=3D"AR-SA" style=3D"font-size:26pt;line-height:115%;font-family:&qu=
ot;AlSharkTitle Black&quot;,sans-serif"><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span>)</span></u></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:115%;margin:0cm 0cm=
 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sa=
ns-serif"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:115%;fon=
t-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D9=85=D8=AD=D8=A7=D9=
=88=D8=B1 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 68pt 0.0001pt 0cm;line-height:115%;direction:rtl;unicode-bidi:embed;font-=
size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=A5=
=D8=B7=D8=A7=D8=B1 =D8=A7=D9=84=D9=86=D8=B8=D8=A7=D9=85=D9=8A =D9=84=D8=AD=
=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A7=D8=AA</span><=
span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;font-family:Ar=
ial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:115%;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;li=
ne-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;f=
ont-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-st=
retch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New R=
oman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D9=85=D8=B3=D8=A4=
=D9=88=D9=84=D9=8A=D8=A7=D8=AA =D9=85=D8=AC=D9=84=D8=B3 =D8=A7=D9=84=D8=A5=
=D8=AF=D8=A7=D8=B1=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:18pt=
;line-height:115%;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:115%;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;li=
ne-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;f=
ont-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-st=
retch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New R=
oman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D9=84=D8=AC=D8=A7=
=D9=86 =D9=85=D8=AC=D9=84=D8=B3 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
(=D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9=D8=8C =D8=A7=D9=84=D8=AA=
=D8=B1=D8=B4=D9=8A=D8=AD=D8=A7=D8=AA=D8=8C =D8=A7=D9=84=D9=85=D9=83=D8=A7=
=D9=81=D8=A2=D8=AA)</span><span lang=3D"AR-SA" style=3D"font-size:18pt;line=
-height:115%;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:115%;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;li=
ne-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;f=
ont-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-st=
retch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New R=
oman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=AD=D9=82=D9=88=
=D9=82 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D9=87=D9=85=D9=8A=D9=86 =D9=88=D8=A3=
=D8=B5=D8=AD=D8=A7=D8=A8 =D8=A7=D9=84=D9=85=D8=B5=D8=A7=D9=84=D8=AD</span><=
span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;font-family:Ar=
ial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 68pt 8pt 0cm;line-height:115%;direction:rtl;unicode-bidi:embed;font-size:1=
1pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-heig=
ht:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;font-siz=
e-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stretch:n=
ormal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&qu=
ot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=A5=
=D9=81=D8=B5=D8=A7=D8=AD =D9=88=D8=A7=D9=84=D8=B4=D9=81=D8=A7=D9=81=D9=8A=
=D8=A9</span><span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></=
span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;line-height:115%;margin:0cm 0cm 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"gmail-MsoListParagraph" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;line-height:115%;margin:0cm 36pt 8pt 0cm;direction:rtl;uni=
code-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=
=3D"font-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">3.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;font-size-adjust:none;font-=
kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt=
;line-height:normal;font-family:&quot;Times New Roman&quot;">
</span></span><span dir=3D"RTL"></span><u><span lang=3D"AR-SA" style=3D"fon=
t-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,san=
s-serif">=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=
=B9 =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A</span></u></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:115%;margin:0cm 0cm=
 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sa=
ns-serif"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:115%;fon=
t-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D9=85=D8=AD=D8=A7=D9=
=88=D8=B1 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;f=
ont-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust:=
none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D9=85=D9=81=D9=87=D9=88=D9=85
=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AC=
=D9=87=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9</span><=
span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif"><=
/span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=AD=D9=88=D9=83=D9=85=D8=A9
=D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1</span><=
span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif"><=
/span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A7=D9=84=D9=86=D8=B2=D8=A7=D9=87=
=D8=A9
=D9=88=D9=85=D9=83=D8=A7=D9=81=D8=AD=D8=A9 =D8=A7=D9=84=D9=81=D8=B3=D8=A7=
=D8=AF</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial=
,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D9=82=D9=8A=D8=A7=D8=B3
=D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=
=D9=8A</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial=
,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 68pt 8pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;font-fa=
mily:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;font-size-adjust:none;f=
ont-kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=
=D8=A7=D9=84
=D9=88=D8=A7=D9=84=D8=B1=D9=82=D8=A7=D8=A8=D8=A9 =D8=A7=D9=84=D8=AD=D9=83=
=D9=88=D9=85=D9=8A=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:18pt=
;font-family:Arial,sans-serif"></span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;line-height:115%;margin:0cm 0cm 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"gmail-MsoListParagraph" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;line-height:115%;margin:0cm 36pt 8pt 0cm;direction:rtl;uni=
code-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=
=3D"font-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">4.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;font-size-adjust:none;font-=
kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt=
;line-height:normal;font-family:&quot;Times New Roman&quot;">
</span></span><span dir=3D"RTL"></span><u><span lang=3D"AR-SA" style=3D"fon=
t-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,san=
s-serif">=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=
=B7=D8=B1 =D9=88=D8=A7=D9=84=D8=A7=D9=84=D8=AA=D8=B2=D8=A7=D9=85
(</span></u><u><span dir=3D"LTR" style=3D"font-size:26pt;line-height:115%;f=
ont-family:&quot;AlSharkTitle Black&quot;,sans-serif">GRC</span></u><span d=
ir=3D"RTL"></span><span dir=3D"RTL"></span><u><span lang=3D"AR-SA" style=3D=
"font-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;=
,sans-serif"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>)</span></u>=
</p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0cm 0=
cm 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;=
AlSharkTitle Black&quot;,sans-serif">=D9=85=D8=AD=D8=A7=D9=88=D8=B1 =D8=A7=
=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;f=
ont-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust:=
none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D9=85=D9=81=D9=87=D9=88=D9=85
</span><span dir=3D"LTR" style=3D"font-size:18pt">GRC</span><span lang=3D"A=
R-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
=D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=
=D8=B3=D9=8A=D8=A9 </span><span dir=3D"LTR" style=3D"font-size:18pt">ERM</s=
pan><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-ser=
if"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=
=D8=A7=D9=84
=D9=84=D9=84=D8=A3=D9=86=D8=B8=D9=85=D8=A9 =D9=88=D8=A7=D9=84=D9=84=D9=88=
=D8=A7=D8=A6=D8=AD</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-=
family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=AF=D9=88=D8=B1
=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=81=D9=8A =D8=AA=D9=82=D9=84=
=D9=8A=D9=84 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1</span><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 68pt 8pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;font-fa=
mily:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;font-size-adjust:none;f=
ont-kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=B1=D8=A8=D8=B7
=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A8=D8=A7=D9=84=D8=A7=D8=B3=
=D8=AA=D8=AF=D8=A7=D9=85=D8=A9</span><span lang=3D"AR-SA" style=3D"font-siz=
e:18pt;font-family:Arial,sans-serif"></span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;line-height:115%;margin:0cm 0cm 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"gmail-MsoListParagraph" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;line-height:115%;margin:0cm 36pt 8pt 0cm;direction:rtl;uni=
code-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=
=3D"font-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">5.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;font-size-adjust:none;font-=
kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt=
;line-height:normal;font-family:&quot;Times New Roman&quot;">
</span></span><span dir=3D"RTL"></span><u><span lang=3D"AR-SA" style=3D"fon=
t-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,san=
s-serif">=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=
=AC=D8=B9=D8=A9 =D8=A7=D9=84=D8=AF=D8=A7=D8=AE=D9=84=D9=8A=D8=A9</span></u>=
</p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:115%;margin:0cm 0cm=
 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sa=
ns-serif"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:115%;fon=
t-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D9=85=D8=AD=D8=A7=D9=
=88=D8=B1 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;f=
ont-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust:=
none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=AF=D9=88=D8=B1
=D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9 =D8=A7=D9=84=D8=AF=D8=A7=
=D8=AE=D9=84=D9=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=
=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial=
,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=B9=D9=84=D8=A7=D9=82=
=D8=A9
=D8=A8=D9=8A=D9=86 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9 =D9=88=
=D9=85=D8=AC=D9=84=D8=B3 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9</span><=
span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif"><=
/span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A7=D8=B3=D8=AA=D9=82=D9=84=D8=A7=
=D9=84=D9=8A=D8=A9
=D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=AC=D8=B9 =D8=A7=D9=84=D8=AF=D8=A7=D8=AE=
=D9=84=D9=8A</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family=
:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=AA=D9=82=D8=A7=D8=B1=D9=8A=D8=B1
=D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9</span><span lang=3D"AR-SA"=
 style=3D"font-size:18pt;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 68pt 8pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;font-fa=
mily:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;font-size-adjust:none;f=
ont-kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A7=D9=84=D9=85=D8=B9=D8=A7=D9=8A=
=D9=8A=D8=B1
=D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9 =D9=84=D9=84=D9=85=D8=B1=D8=A7=
=D8=AC=D8=B9=D8=A9 =D8=A7=D9=84=D8=AF=D8=A7=D8=AE=D9=84=D9=8A=D8=A9</span><=
span dir=3D"LTR" style=3D"font-size:18pt"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0cm 0=
cm 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,=
sans-serif">=C2=A0</span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;line-height:normal;margin:0cm 0cm 8pt;direction:rtl;unicode-bidi:embe=
d;font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D=
"font-size:18pt">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"gmail-MsoListParagraph" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;line-height:115%;margin:0cm 36pt 8pt 0cm;direction:rtl;uni=
code-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=
=3D"font-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">6.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;font-size-adjust:none;font-=
kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt=
;line-height:normal;font-family:&quot;Times New Roman&quot;">
</span></span><span dir=3D"RTL"></span><u><span lang=3D"AR-SA" style=3D"fon=
t-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,san=
s-serif">=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=
=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</span></u></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:115%;margin:0cm 0cm=
 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sa=
ns-serif"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:115%;fon=
t-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D9=85=D8=AD=D8=A7=D9=
=88=D8=B1 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;f=
ont-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust:=
none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=AF=D9=88=D8=B1
=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=
=D8=B4=D8=B1=D9=8A=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:18pt=
;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=B9=D8=AF=D8=A7=D9=84=
=D8=A9
=D9=88=D8=AA=D9=83=D8=A7=D9=81=D8=A4 =D8=A7=D9=84=D9=81=D8=B1=D8=B5</span><=
span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif"><=
/span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=AD=D9=88=D9=83=D9=85=D8=A9
=D8=A7=D9=84=D8=AA=D9=88=D8=B8=D9=8A=D9=81 =D9=88=D8=A7=D9=84=D8=AA=D8=B1=
=D9=82=D9=8A=D8=A7=D8=AA</span><span lang=3D"AR-SA" style=3D"font-size:18pt=
;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
=D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=A7=
=D8=A1=D9=84=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-=
family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 68pt 8pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;font-fa=
mily:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;font-size-adjust:none;f=
ont-kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A3=D8=AE=D9=84=D8=A7=D9=82=D9=8A=
=D8=A7=D8=AA
=D8=A7=D9=84=D8=B9=D9=85=D9=84 =D9=88=D8=A7=D9=84=D8=B3=D9=84=D9=88=D9=83 =
=D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A</span><span lang=3D"AR-SA" style=
=3D"font-size:18pt;font-family:Arial,sans-serif"></span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;line-height:115%;margin:0cm 0cm 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"gmail-MsoListParagraph" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;line-height:115%;margin:0cm 36pt 8pt 0cm;direction:rtl;uni=
code-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=
=3D"font-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">7.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;font-size-adjust:none;font-=
kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt=
;line-height:normal;font-family:&quot;Times New Roman&quot;">
</span></span><span dir=3D"RTL"></span><u><span lang=3D"AR-SA" style=3D"fon=
t-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,san=
s-serif">=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=AA=D9=82=D9=86=D9=8A=D8=A9 =D8=
=A7=D9=84=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D8=
=AA=D8=AD=D9=88=D9=84
=D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A</span></u></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0cm 0=
cm 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;=
AlSharkTitle Black&quot;,sans-serif">=D9=85=D8=AD=D8=A7=D9=88=D8=B1 =D8=A7=
=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;f=
ont-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust:=
none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D9=85=D9=81=D9=87=D9=88=D9=85
=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=AA=D9=82=D9=86=D9=8A=D8=A9 =D8=A7=D9=84=
=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA</span><span lang=3D"AR-SA" style=
=3D"font-size:18pt;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D9=85=D9=88=D8=A7=D8=A1=D9=85=D8=A9
=D8=A7=D9=84=D8=AA=D9=82=D9=86=D9=8A=D8=A9 =D9=85=D8=B9 =D8=A3=D9=87=D8=AF=
=D8=A7=D9=81 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A9</span><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
=D8=A3=D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA</=
span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-se=
rif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 68pt 0.0001pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
=D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D8=AE=
=D8=B5=D9=88=D8=B5=D9=8A=D8=A9</span><span lang=3D"AR-SA" style=3D"font-siz=
e:18pt;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 68pt 8pt 0cm;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;font-fa=
mily:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;font-size-adjust:none;f=
ont-kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A3=D8=B7=D8=B1
</span><span dir=3D"LTR" style=3D"font-size:18pt">COBIT</span><span dir=3D"=
RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-siz=
e:18pt;font-family:Arial,sans-serif"><span dir=3D"RTL"></span><span dir=3D"=
RTL"></span> =D9=88</span><span dir=3D"LTR" style=3D"font-size:18pt">IT Gov=
ernance</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Aria=
l,sans-serif"></span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;line-height:115%;margin:0cm 0cm 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"gmail-MsoListParagraph" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;line-height:115%;margin:0cm 36pt 8pt 0cm;direction:rtl;uni=
code-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=
=3D"font-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">8.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;font-size-adjust:none;font-=
kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt=
;line-height:normal;font-family:&quot;Times New Roman&quot;">
</span></span><span dir=3D"RTL"></span><u><span lang=3D"AR-SA" style=3D"fon=
t-size:26pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,san=
s-serif">=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=
=AF=D8=A7=D9=85=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=
=8A=D8=A9
=D8=A7=D9=84=D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D9=8A=D8=A9</span></u></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0cm 0=
cm 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;=
AlSharkTitle Black&quot;,sans-serif">=D9=85=D8=AD=D8=A7=D9=88=D8=B1 =D8=A7=
=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"line-heig=
ht:normal;margin:0cm 36pt 0.0001pt 0cm;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;f=
ont-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust:=
none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D9=85=D9=81=D9=87=D9=88=D9=85
=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=
=D8=AF=D8=A7=D9=85=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:18pt=
;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0cm 36pt 0.0001pt 0cm;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span dir=3D"LTR" style=3D"font-size=
:18pt">ESG</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span la=
ng=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif"><span di=
r=3D"RTL"></span><span dir=3D"RTL"></span> (=D8=A7=D9=84=D8=A8=D9=8A=D8=A6=
=D8=A9 =E2=80=93 =D8=A7=D9=84=D9=85=D8=AC=D8=AA=D9=85=D8=B9 =E2=80=93 =D8=
=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9)</span><span lang=3D"AR-SA" style=
=3D"font-size:18pt;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0cm 36pt 0.0001pt 0cm;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A7=D9=84=D9=85=D8=B3=D8=A4=D9=88=
=D9=84=D9=8A=D8=A9
=D8=A7=D9=84=D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D9=8A=D8=A9 =D9=84=D9=84=
=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA</span><span lang=3D"AR-SA" style=3D"fo=
nt-size:18pt;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0cm 36pt 0.0001pt 0cm;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=AA=D9=82=D8=A7=D8=B1=
=D9=8A=D8=B1
=D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span><span l=
ang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif"></span>=
</p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"text-align=
:justify;line-height:normal;margin:0cm 36pt 8pt 0cm;direction:rtl;unicode-b=
idi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=3D"fon=
t-size:18pt;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font=
-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stret=
ch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roma=
n&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=
=D8=A9
=D9=88=D8=AF=D8=B9=D9=85 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=
=D8=A9 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=D8=A9</span><span dir=3D"=
LTR" style=3D"font-size:18pt"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;line-height:=
normal;margin:0cm 0cm 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;f=
ont-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:18pt=
;font-family:Arial,sans-serif">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0cm 0=
cm 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;=
AlSharkTitle Black&quot;,sans-serif">=D8=A7=D9=84=D9=85=D9=85=D9=8A=D8=B2=
=D8=A7=D8=AA:</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-famil=
y:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"line-heig=
ht:normal;margin:0cm 36pt 0.0001pt 0cm;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;f=
ont-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust:=
none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Segoe UI Symbol&quot;,sans-serif">=E2=9C=94</spa=
n><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif=
">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=B4=D9=87=D8=A7=D8=AF=D8=A7=D8=AA</span><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0cm 36pt 0.0001pt 0cm;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Segoe UI Symbol&quot;,sans-serif">=E2=9C=94</spa=
n><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif=
">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=AA=D9=86=D9=81=D9=8A=D8=B0</span><span lang=3D"AR-SA" style=3D"f=
ont-size:18pt;font-family:Arial,sans-serif">
&quot;</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial=
,sans-serif">=D8=B9=D9=86</span><span lang=3D"AR-SA" style=3D"font-size:18p=
t;font-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=A8=D9=8F=D8=B9=D8=AF</span><span lang=3D"AR-SA" style=3D"font-si=
ze:18pt;font-family:Arial,sans-serif">&quot;
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=E2=80=93</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-fa=
mily:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=A3=D9=88=D9=82=D8=A7=D8=AA</span><span lang=3D"AR-SA" style=3D"f=
ont-size:18pt;font-family:Arial,sans-serif">
=D9=85=D8=B1=D9=86=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:18pt=
;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0cm 36pt 0.0001pt 0cm;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;=
font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;font-size-adjust=
:none;font-kerning:auto;font-feature-settings:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Segoe UI Symbol&quot;,sans-serif">=E2=9C=94</spa=
n><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif=
">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA</span><span lang=3D"AR-SA=
" style=3D"font-size:18pt;font-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=B9=D9=85=D9=84=D9=8A=D8=A9</span><span lang=3D"AR-SA" style=3D"f=
ont-size:18pt;font-family:Arial,sans-serif">
+ </span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,san=
s-serif">=D9=86=D9=85=D8=A7=D8=B0=D8=AC</span><span lang=3D"AR-SA" style=3D=
"font-size:18pt;font-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=AC=D8=A7=D9=87=D8=B2=D8=A9</span><span lang=3D"AR-SA" style=3D"f=
ont-size:18pt;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"text-ali=
gn:justify;line-height:normal;margin:0cm 36pt 0.0001pt 0cm;direction:rtl;un=
icode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=
=3D"font-size:18pt;font-family:Wingdings">=C2=A7<span style=3D"font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;font-size-adjust:none;font-kerning:auto;font-feature-settings:normal;fon=
t-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times N=
ew Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Segoe UI Symbol&quot;,sans-serif">=E2=9C=94</spa=
n><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif=
">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=AF=D8=B9=D9=85</span><span lang=3D"AR-SA" style=3D"font-size:18p=
t;font-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D9=81=D9=86=D9=8A</span><span lang=3D"AR-SA" style=3D"font-size:18p=
t;font-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D9=88=D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9</span><span lang=3D"AR-SA=
" style=3D"font-size:18pt;font-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=A8=D8=B9=D8=AF</span><span lang=3D"AR-SA" style=3D"font-size:18p=
t;font-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8</span><span dir=3D"LTR" s=
tyle=3D"font-size:18pt"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"text-ali=
gn:justify;line-height:normal;margin:0cm 36pt 0.0001pt 0cm;direction:rtl;un=
icode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span dir=
=3D"RTL"></span><span style=3D"font-size:18pt;font-family:Wingdings">=C2=A7=
<span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-=
feature-settings:normal;font-stretch:normal;font-size:7pt;line-height:norma=
l;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0
</span></span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&q=
uot;Segoe UI Symbol&quot;,sans-serif"><span dir=3D"RTL"></span><span dir=3D=
"RTL"></span>=E2=9C=94</span><span lang=3D"AR-SA" style=3D"font-size:18pt;f=
ont-family:Arial,sans-serif">
8 =D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9=
 =D9=85=D8=AA=D9=83=D8=A7=D9=85=D9=84=D8=A9</span><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:Arial,sans-serif"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"text-ali=
gn:justify;line-height:normal;margin:0cm 36pt 0.0001pt 0cm;direction:rtl;un=
icode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=
=3D"font-size:18pt;font-family:Wingdings">=C2=A7<span style=3D"font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;font-size-adjust:none;font-kerning:auto;font-feature-settings:normal;fon=
t-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times N=
ew Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Segoe UI Symbol&quot;,sans-serif">=E2=9C=94</spa=
n><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif=
">
=D9=8A=D8=B5=D9=84=D8=AD =D9=83=D9=85=D8=B3=D8=A7=D8=B1 =D8=AA=D8=AF=D8=B1=
=D9=8A=D8=A8=D9=8A =D8=A3=D9=88 =D8=AF=D8=A8=D9=84=D9=88=D9=85 =D9=85=D8=B5=
=D8=BA=D8=B1 =D9=81=D9=8A =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9</span>=
<span dir=3D"LTR" style=3D"font-size:18pt"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"line-heigh=
t:normal;margin:0cm 36pt 8pt 0cm;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span dir=3D"RTL"></span><span style=
=3D"font-size:18pt;font-family:Wingdings">=C2=A7<span style=3D"font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;font-size-adjust:none;font-kerning:auto;font-feature-settings:normal;fon=
t-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times N=
ew Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&q=
uot;Segoe UI Symbol&quot;,sans-serif"><span dir=3D"RTL"></span><span dir=3D=
"RTL"></span>=E2=9C=94</span><span lang=3D"AR-SA" style=3D"font-size:18pt;f=
ont-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D9=85=D9=86=D8=A7=D8=B3=D8=A8</span><span lang=3D"AR-SA" style=3D"f=
ont-size:18pt;font-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D9=84=D9=84=D9=85=D9=88=D8=B8=D9=81=D9=8A=D9=86</span><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=E2=80=93</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-fa=
mily:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=A7=D9=84=D9=87=D9=8A=D8=A6=D8=A7=D8=AA</span><span lang=3D"AR-SA=
" style=3D"font-size:18pt;font-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=E2=80=93</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-fa=
mily:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=A7=D9=84=D9=85=D8=AF=D8=B1=D8=A8=D9=8A=D9=86</span><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=E2=80=93</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-fa=
mily:Arial,sans-serif">
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-=
serif">=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D9=8A=D9=86</span><span l=
ang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif"> </span=
><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial,sans-serif"=
>=D9=84=D9=84=D9=82=D8=B7=D8=A7=D8=B9
=D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A =D9=88=D8=A7=D9=84=D8=AE=D8=A7=
=D8=B5</span><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:Arial=
,sans-serif"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;line-height:=
normal;margin:0cm 0cm 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;f=
ont-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:18pt=
;font-family:Arial,sans-serif">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0cm 0cm 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:20pt;line-height:107%;font-family:Arial,sans-serif">=D8=A8=D9=8A=
=D8=A7=D9=86=D8=A7=D8=AA =D8=A7=D9=84=D9=80=D9=80=D9=80=D8=AA=D9=88=D8=A7=
=D8=B5=D9=84 =D9=84=D9=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=
=D8=A7=D8=B3=D8=AA=D9=81=D8=B3=D8=A7=D8=B1</span><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;line-heig=
ht:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0cm 0cm 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:24pt;line-height:107%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">=D8=A3/
=D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=A7=
=D8=AF =E2=80=93 =D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=
=8A=D8=A8</span></b><span dir=3D"LTR" style=3D"font-size:20pt;line-height:1=
07%"><br>
</span><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:107%;font-f=
amily:Arial,sans-serif">=D8=A7=D9=84=D9=87=D8=A7=D8=AA=D9=81</span><span di=
r=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-s=
ize:20pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></spa=
n>:<br>
</span><i><span dir=3D"LTR" style=3D"font-size:22pt;line-height:107%;font-f=
amily:&quot;Times New Roman&quot;,serif">00201069994399<br>
00201062992510<br>
00201096841626</span></i><span dir=3D"LTR" style=3D"font-size:24pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif"><br>
</span><span lang=3D"AR-SA" style=3D"font-size:24pt;line-height:107%;font-f=
amily:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=A7=D9=84=D8=AC=D9=87=
=D8=A9: =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=
=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:20pt;li=
ne-height:107%"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;line-height:=
normal;margin:0cm 0cm 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;f=
ont-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:18pt=
;font-family:Arial,sans-serif">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;line-height:=
normal;margin:0cm 0cm 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;f=
ont-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"font-size:18pt">=
=C2=A0</span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKnVpBdrtYDb37omqpYX%3DD0uYLGJiiAOaZvkv8Y7LUsMBQ%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CADj1ZKnVpBdrtYDb37omqpYX%3DD0uYLGJiiAOaZvkv8Y7LUsMBQ%40mail=
.gmail.com</a>.<br />

--0000000000001ed785064684270a--
