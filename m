Return-Path: <kasan-dev+bncBAABBJ4FWXEAMGQE6F7ZW2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B303C3E08C
	for <lists+kasan-dev@lfdr.de>; Fri, 07 Nov 2025 01:51:53 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-470fd92ad57sf2516165e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Nov 2025 16:51:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762476713; cv=pass;
        d=google.com; s=arc-20240605;
        b=T6WEwt6JYVW77XbePjbZFYRigAbMIs6xQBUYAkP764FfnNx0PBaeqSPM1/2lu2fzZM
         SI8CvoTDy4b2M3qj8R2GnypJhpm9/6zvunBXbJL6XO1yo/GirhSEKd2LVRzNjB2FKfTo
         +JxDOkZsY77raeQkGgt8Pb8SqJwKH4/ZdRH75nyRwCsANxFAnf88rl+JgeVuMy6eG+Ov
         v89tzdNT0HYIb69gOMJnCIwLxN0QDaPN2OF2M6VoOyxWaqwF2ICySr9QicXkLF4Ojyhu
         xTUUSSWs000gSBTRQjxYixCrORlQeZ/24QracFwKIM8uvUQXi4LMDs4L2NUN59oCaThd
         JJyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:subject:to:from
         :mime-version:message-id:date:dkim-signature;
        bh=YhAx2WixHc9LKFJ+BMfkNHCJZTcMxRiEYHae4hFw5RA=;
        fh=z8+vJYg0ByHjtW3UmRnZsQmBTfKWPhOL3X3rLmUjJzk=;
        b=IeZIlpea2KHqp1ZQG1QnMI33pvhOAgeZZHdl1rQ9BaWm/zUWCgV072eqxJshMX2jS/
         dv6Z0x5LwCCiIr20uFpH5hmxTsY2s79/dtv0bTnGA6aV+wjyPMNxZ9U5+v2XSfR5BDmH
         2VYaDJvQK1VFLQPl/uQqJhl5IGK3wV9vs3i9f0aNHn3MFE8VKrWWTqoXMT1lxxXniEEL
         xfV8oIIg9vtk9RsGdL9C73Dq/qBYclugxxDK73lS1Ar2TtfDakYZmOmtJOU48GrPmP8y
         R7PwxHiM97ZwhfOSFqpEBDaKJ1soOM8cenrhOUMkp8jilKb/U6VN8TxDuZDsUFCBdsos
         4Wgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@onetti.space header.s=mail header.b=ab4WQMUC;
       spf=pass (google.com: domain of info@onetti.space designates 31.25.239.71 as permitted sender) smtp.mailfrom=info@onetti.space;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=onetti.space
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762476713; x=1763081513; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:reply-to:subject:to:from:mime-version:message-id
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=YhAx2WixHc9LKFJ+BMfkNHCJZTcMxRiEYHae4hFw5RA=;
        b=KyICl6kCgXlB3P6mH7q/0UiWAMgt9oIMc19n79Ht3/Ckoj0GYhnkGsRv4iRvYPq8QN
         V0U2pPhOOIY5R/AEiSoBVzDmpm2bo+UqDUsolnzfJum3PEi7gH5n3UDvJ8e7Dq+oKG0u
         zVSceqRxKg8DHLVtfhgR0QZ7efIS/n+0JM62WRuJsWs9Myztq5mxZ9USjrZScQdZ3/8/
         oj0MZdUgdl3SldyNbrRVXddB7vHOjV7Jw6FNNl3mWF5FfOavCkHMwatfwOy+DPzd4eDQ
         outW1WkkcMUIfGjf5nDU8Vz8GQe++IFeNN/vRdgWKIGUjStr3FKP3P/AwWmZO3a3p+K+
         dSpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762476713; x=1763081513;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:reply-to
         :subject:to:from:mime-version:message-id:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=YhAx2WixHc9LKFJ+BMfkNHCJZTcMxRiEYHae4hFw5RA=;
        b=CEQieT2Rtf1YzClDLTyBu6otkb1qcubLJcCCWtDBpHMiVopmNVRX96eaJZxXcYw5nS
         EaP0oI2yLGmBpC5mv4Bm2vrs0WvrGJ/Zr+5xiEuaYydcgdunVccKIzKVZlPVOB+LOvuT
         ojjhAhoUKUwZyw3j+6e3OkEUB0omjDlQz2RfrF8KgX0tu7BZ+M5F8haoA6/PS6Mn1eJw
         ZyEgi57Utyh+SeUG7wec0wv0BxX6nweo4HV16/5NQyubZMf32bPoAOAY5KeFanwA0q5s
         tCN+tZPNguJueIeMeC90Ej19ct5wltw7YLHNLYk3LJRBR5OKxGm8wFZSaEWy4bhDuFtG
         toqw==
X-Forwarded-Encrypted: i=2; AJvYcCVGkg5vivow9XoPnha35zNSnVX09+B5slQc2KpDEkUkwU+OKXxd4O2dfJalqdQ4egMWWRZAXA==@lfdr.de
X-Gm-Message-State: AOJu0YxG4hMtAN0PQBSg5WseQbYQ342PwvMj8nJyW5QmS3Jxij0iazBM
	rp5S3INACHg2IfnIPkM8IjfpjdAsLLkEeuvkbtA5BjNrpwh3f31/oAqV
X-Google-Smtp-Source: AGHT+IGkPuBcKTvFY0K43TYFxOVIdikmG+1eDZ4n3QGbr2+z45cO66u0H/t85ju8QzQqP9TY4yBwTw==
X-Received: by 2002:a05:600c:3b0a:b0:477:59f0:5b68 with SMTP id 5b1f17b1804b1-4776bc86c1emr10309045e9.6.1762476712645;
        Thu, 06 Nov 2025 16:51:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Yot35exygfGQYTQFEERsys+SJENkd6Fa7LmT1Y/OV3nA=="
Received: by 2002:a05:600c:620e:b0:477:54a8:a72a with SMTP id
 5b1f17b1804b1-47762262e03ls7983385e9.0.-pod-prod-05-eu; Thu, 06 Nov 2025
 16:51:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWIkqzjS4Yn1a2Aeo1mrn16TW6PsOq0S6ScwjvmGfh/UyEbxj36ssFy9xD6HGQA91IwdsmfSSgiQs0=@googlegroups.com
X-Received: by 2002:a05:600c:1f88:b0:477:c37:2ea7 with SMTP id 5b1f17b1804b1-4776bcb9d12mr11468225e9.21.1762476710335;
        Thu, 06 Nov 2025 16:51:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762476710; cv=none;
        d=google.com; s=arc-20240605;
        b=DBrJmWmFE+bYPwUpd6HiaTfnCr0EozmnoGbU7OhFWvtM3Bd/oCDphGnSnjOHZ2VFVw
         caW8aNhL8JEL+3G2ljYQCUK9uVn4iziwDdpneF77YUctTWwijW/qgBbAoOG/ZfxFQk9n
         bVKXTtbMJog+eSiCsF2ptf6nUarF+JVdGbhWnlZBhhKQW3d5yJ3eUjtVsPyomMJ86Ukv
         v5qYZCHTIfihKZkdg8rsc4MSyqpBIHhxAdvAMsYw8r85w5l+Xt51z19Ov9aYJ8r2KkMw
         ifIPMNYVofABOBpFwKYUEzePCX/zKnBdue2mwc1lEgm3BKk5ZWWb3Efktyl4bZE8j1oJ
         qkQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=reply-to:subject:to:from:mime-version:dkim-signature:message-id
         :date;
        bh=PPi57nNpIyPyhzKCAAq+NcFZSQKlqtMYCdApwqn+prM=;
        fh=bbbzKcUAVBHds+Tel1r4ONsXjLna6z/nQW09oJv41Y0=;
        b=TfvLiTNaJfbiAU2/iqeXEzfGdsgHPyiYhcoNREUzraSNOcPTs8JXq2URjuG3G2dcIs
         K4fle7S8dwAIVpvIW3X3h4zFfeamylzigdvg2lxXeK8YARzAKopA/oXmSMUk+RGsa5lz
         I3BssBRj4Fjlq2S7jEMazotyygeh7t8tTqVEQa+Hm+OWzQdObT3Jo0lwbrxGjAHGnKcw
         6J+QyjHHzgykcuNH1SfJGhFQ9IqwavnTcBKG93MPjq4lNZGiLj/CzShRRqVcSAHB0lRB
         N/bw5vJbvUZQNcW2omOBPQPrPWGezL28n7dDsdyM7+zs+evkWUpfeo/XpJhCKk1aP6N8
         8qWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@onetti.space header.s=mail header.b=ab4WQMUC;
       spf=pass (google.com: domain of info@onetti.space designates 31.25.239.71 as permitted sender) smtp.mailfrom=info@onetti.space;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=onetti.space
Received: from mail.onetti.space (mail.onetti.space. [31.25.239.71])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42ac67c2486si22827f8f.5.2025.11.06.16.51.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Nov 2025 16:51:50 -0800 (PST)
Received-SPF: pass (google.com: domain of info@onetti.space designates 31.25.239.71 as permitted sender) client-ip=31.25.239.71;
Date: Thu, 06 Nov 2025 16:51:50 -0800 (PST)
Message-ID: <690d42a6.050a0220.2c4cc7.1e1aSMTPIN_ADDED_MISSING@gmr-mx.google.com>
Received: from OBlock11.lan (unknown [31.222.238.6])
	by mail.onetti.space (Postfix) with ESMTPSA id 466D340B38;
	Fri,  7 Nov 2025 00:51:41 +0000 (UTC)
Content-Type: multipart/mixed; boundary="===============4204815248116507496=="
MIME-Version: 1.0
From: "'Info' via kasan-dev" <kasan-dev@googlegroups.com>
To: Info < info@onetti.space>
Subject: FOB/CIF Petroleum sales
Reply-To: standardpt@yandex.kz
X-Original-Sender:  info@onetti.space
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@onetti.space header.s=mail header.b=ab4WQMUC;       spf=pass
 (google.com: domain of info@onetti.space designates 31.25.239.71 as permitted
 sender) smtp.mailfrom=info@onetti.space;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=onetti.space
X-Original-From: Info < info@onetti.space>
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

--===============4204815248116507496==
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0

Dear oil buyer, this is urgent information's of exported products for sale.
We have, Jet Fuel, EN590, LNG, LGP, D6, UREA, DAP available for sales in FOB/CIF Bases, same as well to other product on sales on CIF/FOB, mainly deliver in a timely manner for a ready company to purchase.
You can trust in us to help you for any fuel inquiries if you request.
Please contact back for cargos going to Rotterdam, Houston, Fujairah, Chinese ports and Singapore also ready. Orders for other ports are also accepted.
Regards,
Seytzhanov Nurzhan.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/690d42a6.050a0220.2c4cc7.1e1aSMTPIN_ADDED_MISSING%40gmr-mx.google.com.

--===============4204815248116507496==--
