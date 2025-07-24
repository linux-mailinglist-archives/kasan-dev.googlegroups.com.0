Return-Path: <kasan-dev+bncBDP6DZOSRENBBQOKRLCAMGQEVFFKKUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id D345DB1131E
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 23:27:31 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-31218e2d5b0sf2165392a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 14:27:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753392450; cv=pass;
        d=google.com; s=arc-20240605;
        b=eOmlbgsdEMPcAt9KP0kudv8bkqs49ME9C91Wsbwk6/e53b6n3fDp47AvRUsiFnbX7V
         EDrmNzRNF4NiM9s4CtQHjJmCpuOa68JCZEVN9afxbPAApnkQMNB8mMlZ5hbL+kYAer4B
         /58BHFkiRWptBH6IpZYXfBnKhgXBl4V5Xloyxo/DnAVCUe4iGRb8a1w6aQ97NiZsweag
         lW9GYZKVAQsFG4XFV+QCVU9tx3EJDJqdIaw9hz3o1LuOC9ZglXN6g595HReNqJeajPRI
         lFl0CwwQdFnZERHVE3Te/Oi8R+rhlwEGhS6QPrtUe1NnyCR7kiV7ujjNz99v3kyC8W1p
         nuBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=yia4q15WnZM0HQhW8NRKZawpU6qpSOh7AVW2j2iphDw=;
        fh=tmdNWGkWifc/d83D1k7Q9/RWEfihqHC89hQNHJ+EHDc=;
        b=Ct/9aAuwOLlkiAIUQI/+OxT7Sk3xIauogzsMDC8OGLsB9yfFgMpoH2C3AzcVuO918x
         IGD0Iu6YvVQfefQmxWzW53tJPg5nlL9sGXEHA4Ynlvx1dq6EsVQpvvDLSCiIKr+PvQnK
         dBlfvqyuwkZ5nFpac01JYo7J+532mVnZxRJeH6nWbKPpLx75aSWYcZOnOPBHyhJJbXS2
         vB7Q8EjAJ9plLDWx3i3yuhwKVN0m3tEiFHaZfCsHSspqiXQ8Ngj5/EARF0GpFED5Xx1u
         Vr1W/ZLVxyEDhMsOVPgnCRAm+ts40T9knB0SbZHyO7OgJ7fpag2lGc5J7o+tbIbm08Ry
         RaHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=google header.b=JlYAj8+7;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753392450; x=1753997250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yia4q15WnZM0HQhW8NRKZawpU6qpSOh7AVW2j2iphDw=;
        b=e1+sNvdgfktWZ8cMq4UJwm5iTyw6gVWtJkr0efxDlP8EAmFJ/8ecu96a17N51PbyzH
         bILtEJkxnXnCldZblCbU/+u2YtwBJoVIRowcZ5PbegCcgYKb200xjrmBD8AiQmRq2Ea6
         CoHN/mROwgdVzYHikIzB4FSMY7NK/fmUORzzLcGLTAb7gFrrpMiV1zBv138CiA08hsJA
         uqETe2xjee3lHkcmzlrqH9c9qhqAtBZ9uxvhPT1TjlHDv/KAVy9hmdZ+37m6yp6Qye5g
         vqeAyXAZTzgvQ+ZUTjpkk7ttYz52wZ/KmStBF5gyZA/+kovj8gAVobVn9i5dmLX3EBcZ
         iudw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753392450; x=1753997250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yia4q15WnZM0HQhW8NRKZawpU6qpSOh7AVW2j2iphDw=;
        b=kTW2oA3OkYqSvmRkue5lKP9slzuoIQYtVE7Bu7MGuAHpkzkpZ5ZlV76P3cQf/I40az
         6npMgntBYZpS5lURLQ4l8gUepeEfPA38pBPIWrBggi7esrXFzqBEKLpLiWbYnZq2/yZ5
         uJU1OBqSvUAaDoDEAijp7cBGNI2UmXPO2n8UyMNjYPyDiX6vz9QkyOMu4DO+iMwKStrg
         6KN4gEYRKwKOWwBZHTzHVroeL0A8p0YGP7bvPYxuxBTYWhYppOZ0iC0IOY6ceexaoMui
         aRRwYOlZOySU56BuMcRNKkUqkF7H5kHWqAOfCGSzmVWrlthcgKVYVB8begHpy31lnuLZ
         EgVg==
X-Forwarded-Encrypted: i=2; AJvYcCXfK2g9JdWHCOzdCiEvY5pqNODF4P0xgj0PUzWx5sYOV2oyDOpn9BzIrbC0M9cxBZSDy8sp6w==@lfdr.de
X-Gm-Message-State: AOJu0YyVMzitdBtvElpO6wVr6ulM5hOcPWuRX/uai4ee/vl/AKv1Zj93
	tobAKbbA1uo4SMJISEMj6j8U/Qo7jjuU/qo1F5gFqVwnakERHH3BY/8J
X-Google-Smtp-Source: AGHT+IErv6h1JLPMWLzwxoVIae7CT0ZZgc6aeWsJyhi3ovvC/qUHzBNBMvCaBtDgaJD32Cn56zRPSA==
X-Received: by 2002:a17:90b:5844:b0:311:c970:c9c0 with SMTP id 98e67ed59e1d1-31e507b3fd6mr10267391a91.22.1753392450188;
        Thu, 24 Jul 2025 14:27:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfJF/LX6hAPBrNRKjpL3z6jagR+QzPyA58LkFz4xIqRiQ==
Received: by 2002:a17:90a:108f:b0:314:21ab:c5d3 with SMTP id
 98e67ed59e1d1-31e5fabd0afls1368181a91.1.-pod-prod-06-us; Thu, 24 Jul 2025
 14:27:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8qSBULK4rw/xOzVoZbqF+KDGAXpqQnCJcwT/wXFU3ySnoBMzlHQEXp1ssSbGO0X5m06b3ULAnpHA=@googlegroups.com
X-Received: by 2002:a17:90b:54ce:b0:312:1d2d:18e2 with SMTP id 98e67ed59e1d1-31e507b3c7cmr12123521a91.20.1753392448811;
        Thu, 24 Jul 2025 14:27:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753392448; cv=none;
        d=google.com; s=arc-20240605;
        b=E34wSsD3k3T7dLFYVBi6mKF2rVvY2ugFOkwnl/RdnPGj7KU/1Nw9GDD1c9L5x9iRwT
         +7r0cvwzIcXZAtLJd2lG8Fi/SB45UiVyj1EsplpdMXqddVwCF+jdGFnMxp2/WwbWP4kK
         bls3BHyH2EQFVKIe6JSgzK1L6MjjW2CptkQ8XuZiOl9iyIotN5dy6mcTC8smuOvyNx/K
         PrnFIMOVpD0Qm4e9YmjjhZ93L1C1puZDyAQ8JRa4fF6lp/zjjLds2nFHoepym/IiLYU/
         b/hCrDlSdUcrmxlnnBdIahwnwcZPtsCLDEcAdlRImKiDYZpLShdfjVEBoGMzlE/Az3Lp
         6mJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=eb7LwTrwfKZRGwsWl7FQwuOc+LHKc/Q1TZHaaM57R8o=;
        fh=5bvWh/h+YM9f1pGCyXMESjf0XpcN4hviPXp4oEaeo+U=;
        b=jeEP4sDdpfGYwfDrmbaslLfQLftux8JEqJdQf7lPiJMLiMlRGO0Dy0D00jPcF1xUKt
         n4Fcy/nm1mgpnrFzE79xxcxBnzGVJi/ZRfTGey1XjtBpEfkjVOvWGxu2pvFYHS/RBiQc
         SkulUKFGYKpziDbIa4BXvX32spZjoOGM7wiWAw60QNlRISeMAMSLCyo+DSwmM2w+qmRb
         yKp/idRCTCRB+2KoFQoKzq0N8KYRpYlUzUfP3cjUV7nnAPlEnFYXBEjWjLBGdqV67A+4
         9XLtGftwJoadxYEs5rYCJHz2PXi/wUQbsoeNwdO0IyVSuF2tbOHYHZRiuN7EiL0DTpnX
         sIZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=google header.b=JlYAj8+7;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31e60979132si148817a91.0.2025.07.24.14.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Jul 2025 14:27:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-6fd0a3cd326so16139156d6.1
        for <kasan-dev@googlegroups.com>; Thu, 24 Jul 2025 14:27:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUwG1gp0N7Xih3JARfGS9leUfDNSzTKQqznPRh5n7zyVmrnZgbN79BTswHd/hJS6NI8QBKw1VNvW7Y=@googlegroups.com
X-Gm-Gg: ASbGnctdNVj5xXszGY5r5+jL+OzeaPV02EZ7Rul/GD6dlS4egJVMt54zZC5zagYODgr
	6u2qSoBKALnTDK4Ydx4gSUKb2C4QAe09DLWRT28FyPOZdb06GLBebusbWmsQXKqjy2/LhQ/jM6m
	eFIOol6jhJda9/ypjEuiFjCNtzcenSR/XL2q8SDEmf+2lIy5Z9XEszBxi/QApGGNh+ozO5Rc61X
	XWJTVb75Gf6JEkYRABeUAiOdd15tYU36YLhz5/YNQe6gkuK5+p4u9wHRZRqf5zZ/Ijb4bmylL8Q
	sThuWlCMjzQr1i5+n0LMWF++mScVjaeKAzHqedCAGrnS1Wer4BvA18L9nT1ay7hTIT/1CC0YaP+
	tjOJni/0v8M3/thuRR+w4h6JyQ/JQM2aOplACrW2D3JEl0SoJPJ2ufIYC/+njBt3ovYv2WqES
X-Received: by 2002:a05:6214:500d:b0:6fb:4e82:6e8 with SMTP id 6a1803df08f44-7070051b347mr106591216d6.14.1753392447547;
        Thu, 24 Jul 2025 14:27:27 -0700 (PDT)
Received: from [10.67.48.245] ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-7070faec0b9sm18388806d6.5.2025.07.24.14.27.21
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Jul 2025 14:27:26 -0700 (PDT)
Message-ID: <136af381-5c31-49dd-98fe-1703a2cd57df@broadcom.com>
Date: Thu, 24 Jul 2025 14:27:20 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 12/16] MAINTAINERS: Include dmesg.py under PRINTK entry
To: John Ogness <john.ogness@linutronix.de>, linux-kernel@vger.kernel.org
Cc: Jan Kiszka <jan.kiszka@siemens.com>, Kieran Bingham
 <kbingham@kernel.org>, Michael Turquette <mturquette@baylibre.com>,
 Stephen Boyd <sboyd@kernel.org>, Dennis Zhou <dennis@kernel.org>,
 Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@gentwo.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 "Rafael J. Wysocki" <rafael@kernel.org>, Danilo Krummrich <dakr@kernel.org>,
 Petr Mladek <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Ulf Hansson <ulf.hansson@linaro.org>, Thomas Gleixner <tglx@linutronix.de>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Luis Chamberlain <mcgrof@kernel.org>, Petr Pavlu <petr.pavlu@suse.com>,
 Sami Tolvanen <samitolvanen@google.com>, Daniel Gomez
 <da.gomez@samsung.com>, Kent Overstreet <kent.overstreet@linux.dev>,
 Anna-Maria Behnsen <anna-maria@linutronix.de>,
 Frederic Weisbecker <frederic@kernel.org>,
 Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
 Uladzislau Rezki <urezki@gmail.com>, Matthew Wilcox <willy@infradead.org>,
 Kuan-Ying Lee <kuan-ying.lee@canonical.com>,
 Ilya Leoshkevich <iii@linux.ibm.com>, Etienne Buira <etienne.buira@free.fr>,
 Antonio Quartulli <antonio@mandelbit.com>, Illia Ostapyshyn
 <illia@yshyn.com>, "open list:COMMON CLK FRAMEWORK"
 <linux-clk@vger.kernel.org>,
 "open list:PER-CPU MEMORY ALLOCATOR" <linux-mm@kvack.org>,
 "open list:GENERIC PM DOMAINS" <linux-pm@vger.kernel.org>,
 "open list:KASAN" <kasan-dev@googlegroups.com>,
 "open list:MAPLE TREE" <maple-tree@lists.infradead.org>,
 "open list:MODULE SUPPORT" <linux-modules@vger.kernel.org>,
 "open list:PROC FILESYSTEM" <linux-fsdevel@vger.kernel.org>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
 <20250625231053.1134589-13-florian.fainelli@broadcom.com>
 <84v7oic2qx.fsf@jogness.linutronix.de>
Content-Language: en-US
From: "'Florian Fainelli' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=florian.fainelli@broadcom.com; keydata=
 xsBNBFPAG8ABCAC3EO02urEwipgbUNJ1r6oI2Vr/+uE389lSEShN2PmL3MVnzhViSAtrYxeT
 M0Txqn1tOWoIc4QUl6Ggqf5KP6FoRkCrgMMTnUAINsINYXK+3OLe7HjP10h2jDRX4Ajs4Ghs
 JrZOBru6rH0YrgAhr6O5gG7NE1jhly+EsOa2MpwOiXO4DE/YKZGuVe6Bh87WqmILs9KvnNrQ
 PcycQnYKTVpqE95d4M824M5cuRB6D1GrYovCsjA9uxo22kPdOoQRAu5gBBn3AdtALFyQj9DQ
 KQuc39/i/Kt6XLZ/RsBc6qLs+p+JnEuPJngTSfWvzGjpx0nkwCMi4yBb+xk7Hki4kEslABEB
 AAHNMEZsb3JpYW4gRmFpbmVsbGkgPGZsb3JpYW4uZmFpbmVsbGlAYnJvYWRjb20uY29tPsLB
 IQQQAQgAywUCZWl41AUJI+Jo+hcKAAG/SMv+fS3xUQWa0NryPuoRGjsA3SAUAAAAAAAWAAFr
 ZXktdXNhZ2UtbWFza0BwZ3AuY29tjDAUgAAAAAAgAAdwcmVmZXJyZWQtZW1haWwtZW5jb2Rp
 bmdAcGdwLmNvbXBncG1pbWUICwkIBwMCAQoFF4AAAAAZGGxkYXA6Ly9rZXlzLmJyb2FkY29t
 Lm5ldAUbAwAAAAMWAgEFHgEAAAAEFQgJChYhBNXZKpfnkVze1+R8aIExtcQpvGagAAoJEIEx
 tcQpvGagWPEH/2l0DNr9QkTwJUxOoP9wgHfmVhqc0ZlDsBFv91I3BbhGKI5UATbipKNqG13Z
 TsBrJHcrnCqnTRS+8n9/myOF0ng2A4YT0EJnayzHugXm+hrkO5O9UEPJ8a+0553VqyoFhHqA
 zjxj8fUu1px5cbb4R9G4UAySqyeLLeqnYLCKb4+GklGSBGsLMYvLmIDNYlkhMdnnzsSUAS61
 WJYW6jjnzMwuKJ0ZHv7xZvSHyhIsFRiYiEs44kiYjbUUMcXor/uLEuTIazGrE3MahuGdjpT2
 IOjoMiTsbMc0yfhHp6G/2E769oDXMVxCCbMVpA+LUtVIQEA+8Zr6mX0Yk4nDS7OiBlvOwE0E
 U8AbwQEIAKxr71oqe+0+MYCc7WafWEcpQHFUwvYLcdBoOnmJPxDwDRpvU5LhqSPvk/yJdh9k
 4xUDQu3rm1qIW2I9Puk5n/Jz/lZsqGw8T13DKyu8eMcvaA/irm9lX9El27DPHy/0qsxmxVmU
 pu9y9S+BmaMb2CM9IuyxMWEl9ruWFS2jAWh/R8CrdnL6+zLk60R7XGzmSJqF09vYNlJ6Bdbs
 MWDXkYWWP5Ub1ZJGNJQ4qT7g8IN0qXxzLQsmz6tbgLMEHYBGx80bBF8AkdThd6SLhreCN7Uh
 IR/5NXGqotAZao2xlDpJLuOMQtoH9WVNuuxQQZHVd8if+yp6yRJ5DAmIUt5CCPcAEQEAAcLB
 gQQYAQIBKwUCU8AbwgUbDAAAAMBdIAQZAQgABgUCU8AbwQAKCRCTYAaomC8PVQ0VCACWk3n+
 obFABEp5Rg6Qvspi9kWXcwCcfZV41OIYWhXMoc57ssjCand5noZi8bKg0bxw4qsg+9cNgZ3P
 N/DFWcNKcAT3Z2/4fTnJqdJS//YcEhlr8uGs+ZWFcqAPbteFCM4dGDRruo69IrHfyyQGx16s
 CcFlrN8vD066RKevFepb/ml7eYEdN5SRALyEdQMKeCSf3mectdoECEqdF/MWpfWIYQ1hEfdm
 C2Kztm+h3Nkt9ZQLqc3wsPJZmbD9T0c9Rphfypgw/SfTf2/CHoYVkKqwUIzI59itl5Lze+R5
 wDByhWHx2Ud2R7SudmT9XK1e0x7W7a5z11Q6vrzuED5nQvkhAAoJEIExtcQpvGagugcIAJd5
 EYe6KM6Y6RvI6TvHp+QgbU5dxvjqSiSvam0Ms3QrLidCtantcGT2Wz/2PlbZqkoJxMQc40rb
 fXa4xQSvJYj0GWpadrDJUvUu3LEsunDCxdWrmbmwGRKqZraV2oG7YEddmDqOe0Xm/NxeSobc
 MIlnaE6V0U8f5zNHB7Y46yJjjYT/Ds1TJo3pvwevDWPvv6rdBeV07D9s43frUS6xYd1uFxHC
 7dZYWJjZmyUf5evr1W1gCgwLXG0PEi9n3qmz1lelQ8lSocmvxBKtMbX/OKhAfuP/iIwnTsww
 95A2SaPiQZA51NywV8OFgsN0ITl2PlZ4Tp9hHERDe6nQCsNI/Us=
In-Reply-To: <84v7oic2qx.fsf@jogness.linutronix.de>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=google header.b=JlYAj8+7;       spf=pass
 (google.com: domain of florian.fainelli@broadcom.com designates
 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Florian Fainelli <florian.fainelli@broadcom.com>
Reply-To: Florian Fainelli <florian.fainelli@broadcom.com>
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

On 6/26/25 01:43, John Ogness wrote:
> On 2025-06-25, Florian Fainelli <florian.fainelli@broadcom.com> wrote:
>> Include the GDB scripts file under scripts/gdb/linux/dmesg.py under the
>> PRINTK subsystem since it parses internal data structures that depend
>> upon that subsystem.
>>
>> Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
>> ---
>>   MAINTAINERS | 1 +
>>   1 file changed, 1 insertion(+)
>>
>> diff --git a/MAINTAINERS b/MAINTAINERS
>> index 224825ddea83..0931440c890b 100644
>> --- a/MAINTAINERS
>> +++ b/MAINTAINERS
>> @@ -19982,6 +19982,7 @@ S:	Maintained
>>   T:	git git://git.kernel.org/pub/scm/linux/kernel/git/printk/linux.git
>>   F:	include/linux/printk.h
>>   F:	kernel/printk/
>> +F:	scripts/gdb/linux/dmesg.py
> 
> Note that Documentation/admin-guide/kdump/gdbmacros.txt also contains a
> similar macro (dmesg). If something needs fixing in
> scripts/gdb/linux/dmesg.py, it usually needs fixing in
> Documentation/admin-guide/kdump/gdbmacros.txt as well.
> 
> So perhaps while at it, we can also add here:
> 
> F:	Documentation/admin-guide/kdump/gdbmacros.txt

Thanks, v2 coming up.
-- 
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/136af381-5c31-49dd-98fe-1703a2cd57df%40broadcom.com.
