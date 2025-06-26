Return-Path: <kasan-dev+bncBDP6DZOSRENBBUHP6XBAMGQE6YZSLUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 01328AEA3A0
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 18:39:48 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4a44e608379sf42253231cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 09:39:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750955984; cv=pass;
        d=google.com; s=arc-20240605;
        b=fNYdcxiEQcNV1xHQX5W5Q/HmfWQqOC9lup7U/RvuMHDseA6vg6GA9LRjPXl8IlokiY
         cxTEFj4kb3pna8n7aftNyphjM+4njAZNnsmM/+WNmzLyyULg+0c8nF5chY5df5sz58EO
         b25Y4l3anAlJlCGnGqE5N2/Pv1kiuZkIpiRiiuqS2nHr1DLZMchvKDTkraNdEb8UlDEd
         jwj7CqR/KTtaxz7bdCSWvdajOAf5Hk3jYJyNWt/1ATQbOiEafGLJokET/p/KcVwsC+m6
         ld6nxI82SiRDRIczgytonCNh9PpSRJoTkYTnGV7GU3SVzE8TljH7cJarruxs1USBSsws
         6rfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:autocrypt:from
         :content-language:references:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=Szy9qnmTdTU+FzqdnCcyXCYgOb8QEi+ytuO+h4XUEeM=;
        fh=bhHaFwFWwvlv57vy+idblO4OyV2unwOru2f3AX2y8NM=;
        b=kcMI85i2dsU/IZ7xG4zkt5aXalhfjfZ6dgA2L6TvW0GRSICrZReRQJdIORgRoJhwj9
         ySMT/0PRXIll1k+5ZTkrGlzahHoSFth0tC4hj+rq1xOi3X6hIgv2A+wrGFQOkUzczqE4
         cE7xCRvZUwVmreemZHAPSfMN+Wu2aCFDFJSgRO277j93eDEENLt47Zg5VV9fuA/nbjb1
         HeQsnhZceV7pNtsG+SU3hpWOErP8rpmymZYhQ2fs4A4EoF70f3ifREqX1T5aODvQPF2F
         1jJwMeVA7fNOD+OH0U6PjQe1kR+IIYt+YYMSKQ2+ZFuAH7wUvbJSxfDTQvSFuw0JZRph
         ADEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=google header.b=CBUnz0oE;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750955984; x=1751560784; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Szy9qnmTdTU+FzqdnCcyXCYgOb8QEi+ytuO+h4XUEeM=;
        b=KxpA/sZpDiX8gN2zoguHBwIAqWa68rvPLkMkr/i+9aOhiZFBbcAmiOT3W8tDBx0Zl6
         zoViX7ro2vVsGZCueShkkLKjPrX19A+JVHdsL0aUg+CJYy5asSlrmqoM7DeJRL/dsUbk
         ESagombxT7A0vvxRSao8oreheQdWz/wyXz7GeurM+vZvxl3xs3n5KXVv81sruHedaIhn
         XOCah4qe4369Q/Cz9HyfvwS0j5zcRnb02a2/uIX3I9Oj+2CaIVoSic9oiFmy/XPju1uN
         Wa7OZ6IqRhovoMe92Wl5ss2WhkaQa0W/Zd+TW0NJVe90SgZtBWXezK4eO5GesC1+0pui
         1VJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750955984; x=1751560784;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Szy9qnmTdTU+FzqdnCcyXCYgOb8QEi+ytuO+h4XUEeM=;
        b=pu4iYCtx/g8h4ci2EMqlENuZEtlX60OR3xi1VTht6Oi57C9f77YpJf2PeGQcZbRNJ1
         eN04Urza1puiYgustWJmghx/3x9qCVdvMYjKIzJ9DIm7XYo9mstR3Nen3aSIhDEvMaRJ
         S/Hk9y0KZ2C1xwVCEUMWvNPt1W2XbRFNvGr2yOgXZJDmxeSjOAq4wyKGnRXLwC8eixRd
         gsr5MO74Ni5r0dxVkwZC9nW+JsW3yyQsOSjyN6tj92tuPeibbe8wBci6hX8SsiKLUh58
         t+A8SnfCW0PpaSvNbjtAPJTJeVqqcrLCAp9zFYqAjgE23t7N7GXSG5U/HucOoqy902FS
         ONsw==
X-Forwarded-Encrypted: i=2; AJvYcCULi6voCTsOLbpBDyK+KD1BwZXOEJjtyuuvzii4wY9P/+LDqq5Xno/ys3fYXzVCag6p2+7kmw==@lfdr.de
X-Gm-Message-State: AOJu0YyttbpeWZpy5mIMcsdizOhyFT0/jWNYKg1QASg5u0VPLHtrHik/
	fcV344ibNGDdTB14Q8y1oxudS0w3Z/0ofrXPc7WB0az4wzufTAgk0ZWk
X-Google-Smtp-Source: AGHT+IGTo8zayIZPmaF1BE1ay1YU0mJXRmBYEmdtOzXqNMxgcB6hULhbikyP7Gm7IKKkA+WZg3StmQ==
X-Received: by 2002:ad4:4ee4:0:b0:6fa:c246:c363 with SMTP id 6a1803df08f44-6fffdcff913mr3864346d6.13.1750955984180;
        Thu, 26 Jun 2025 09:39:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeTs+PPFzJnySAbBfuz1wS48PeuTCHoZoCk5y5sfXJidw==
Received: by 2002:ad4:596c:0:b0:6fa:bf2a:9be7 with SMTP id 6a1803df08f44-6fd75028de1ls23319636d6.0.-pod-prod-06-us;
 Thu, 26 Jun 2025 09:39:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZ0l5Hr2FyJftf7E0e9zWIFfW+CokGBuwZwHgPUwV33fK6hnUtsnkWdBF9HMg4laSLHkQYzB/p0Tk=@googlegroups.com
X-Received: by 2002:a05:6122:290d:b0:531:236f:1295 with SMTP id 71dfb90a1353d-532ef3c1ee9mr6567823e0c.5.1750955983321;
        Thu, 26 Jun 2025 09:39:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750955983; cv=none;
        d=google.com; s=arc-20240605;
        b=WXx+jszm39sjM1UYY/Mi+5lWqotqAXf/7UeDvj3RHiiN/uGwRruIlRrt2zAu7DLuWl
         ndHLkZumJHRAGQoqs2oW8UtiSGvDmEGrSP0SPwh5ZkmCDFEWXkgKzMmxnfcu6weDFDXC
         flV3bcl68yISaoZrr3qbsqzmup0G971Z2RbrsGkDTK1tEVadAaIMp5/XiAwQHRPwXHBk
         V0kueDckej62eaVHv9bRGwsu1CQMotCQX9BnNe43TJcQLW6BshLIjtln/kaII31Zg5zH
         Pj50HUmGTebl4o6NQy0q09wJd8Q2BcWpvxRkFNAutczJe8bXjOj3++i58d1P3lr7wDAf
         LNSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=kiB7sElStizaKuG4ZG0mE7ZHh4hndYmdW5MwoUlLuUc=;
        fh=1XNKZFnyEKsLMkctRSGBJl+LZ/eCcKnCrACIjJNMPNQ=;
        b=i//hFhOzT7xH69errC8wzv/ouLbhkEwPMf4FCK71C+HnqoFzOS3h0fuwJIGY4FQD2J
         F3X+krQWpw5P/16D8N9Zi6wNHIEhN97YFiugOT/RtQ0xDbH7IdABGx7S+RO4DIU0s/pK
         5JjY0vRHzWLXYjpai0lRpOWroW+Ctkkab+3QbRcJ2y6yURv1CWBsR5UeZwqMPApP8EfV
         DUoe7Pdcm2JM/0XvpMhvmKwZYtymcL4WaAmTsBiCRDbNXHh6SLJQOPJf8jBcgE8jVRcW
         65nc0au67dAU8QjpuzJTdZ7VDzuVqiV0zdkLwX/B9pLPyv5UJAi+S7bwMyZrjIZaIfMA
         DEoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=google header.b=CBUnz0oE;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-533091ac265si11014e0c.4.2025.06.26.09.39.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 09:39:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id 41be03b00d2f7-b26f7d2c1f1so1356957a12.0
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 09:39:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWlv1HHaN6V4AgjctJfPVpeMuC8lDbCJdTY3Z78Grr5BK6Lne1BDwWnqh9USzgXDZiQwATV1XGRCK4=@googlegroups.com
X-Gm-Gg: ASbGncs0U1GDlQZkiKuXNXvqMsqYyITCrSm8gLqOUbg8fAj1xok4aXBT8oogOhwm1qu
	QX1w3RtWHDi9A+QKRozARJy5l8V/7b5bMx0s7jnSluP0+FKPXyBGaPjGY0bS3Rb9MGTL8Ok9Lab
	eQ4jkdLZAYDtYriPgUOvra76liYyiAf8gMBC7J/uDsEJBGFe5xpHXKrmi1VF/irw4uLorhpNTYL
	7VlpqER3gGCL6hzqCnTrxT2u/zLcqnyCZ6HrNBUPSJjKYf6qTYQt6yykLyxmpWnkQrYZE+lXnUO
	5ljin4rXSoHagsm5B1/g3RwdCwKrrkriFrzzG4EWxoI22LW8KjMqPi//5PCNGrP2JRnm3yIxBi/
	8aKZc6NRsqtb+nnzY/dkS+CNlJRevvS6nkaPG
X-Received: by 2002:a17:90b:2e87:b0:314:7e4a:db08 with SMTP id 98e67ed59e1d1-315f2675fc7mr12720722a91.18.1750955982382;
        Thu, 26 Jun 2025 09:39:42 -0700 (PDT)
Received: from [10.67.48.245] ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-318c13921fdsm209101a91.10.2025.06.26.09.39.37
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 09:39:41 -0700 (PDT)
Message-ID: <c66deb8f-774e-4981-accf-4f507943e08c@broadcom.com>
Date: Thu, 26 Jun 2025 09:39:36 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/16] MAINTAINERS: Include GDB scripts under their
 relevant subsystems
To: "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 linux-kernel@vger.kernel.org, Jan Kiszka <jan.kiszka@siemens.com>,
 Kieran Bingham <kbingham@kernel.org>,
 Michael Turquette <mturquette@baylibre.com>, Stephen Boyd
 <sboyd@kernel.org>, Dennis Zhou <dennis@kernel.org>,
 Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@gentwo.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 "Rafael J. Wysocki" <rafael@kernel.org>, Danilo Krummrich <dakr@kernel.org>,
 Petr Mladek <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>,
 John Ogness <john.ogness@linutronix.de>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Ulf Hansson <ulf.hansson@linaro.org>, Thomas Gleixner <tglx@linutronix.de>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
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
 <fynmrmsglw4liexcb37ykutf724lh7zbibilcjpysbmvgtkmes@mtjrfkve4av7>
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
In-Reply-To: <fynmrmsglw4liexcb37ykutf724lh7zbibilcjpysbmvgtkmes@mtjrfkve4av7>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=google header.b=CBUnz0oE;       spf=pass
 (google.com: domain of florian.fainelli@broadcom.com designates
 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
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

On 6/26/25 09:17, Liam R. Howlett wrote:
> * Florian Fainelli <florian.fainelli@broadcom.com> [250625 19:13]:
>> Linux has a number of very useful GDB scripts under scripts/gdb/linux/*
>> that provide OS awareness for debuggers and allows for debugging of a
>> variety of data structures (lists, timers, radix tree, mapletree, etc.)
>> as well as subsystems (clocks, devices, classes, busses, etc.).
>>
>> These scripts are typically maintained in isolation from the subsystem
>> that they parse the data structures and symbols of, which can lead to
>> people playing catch up with fixing bugs or updating the script to work
>> with updates made to the internal APIs/objects etc. Here are some
>> recents examples:
>>
>> https://lore.kernel.org/all/20250601055027.3661480-1-tony.ambardar@gmail.com/
>> https://lore.kernel.org/all/20250619225105.320729-1-florian.fainelli@broadcom.com/
>> https://lore.kernel.org/all/20250625021020.1056930-1-florian.fainelli@broadcom.com/
>>
>> This patch series is intentionally split such that each subsystem
>> maintainer can decide whether to accept the extra
>> review/maintenance/guidance that can be offered when GDB scripts are
>> being updated or added.
> 
> I don't see why you think it was okay to propose this in the way you
> have gone about it.  Looking at the mailing list, you've been around for
> a while.

This should probably have been posted as RFC rather than PATCH, but as I 
indicate in the cover letter this is broken down to allow maintainers 
like yourself to accept/reject

> 
> The file you are telling me about seems to be extremely new and I needed
> to pull akpm/mm-new to discover where it came from.. because you never
> Cc'ed me on the file you are asking me to own.

Yes, that file is very new indeed, and my bad for not copying you on it.

I was not planning on burning an entire day worth of work to transition 
the GDB scripts dumping the interrupt tree away from a radix tree to a 
maple tree. All of which happens with the author of that conversion 
having absolutely no idea that broke anything in the tree because very 
few people know about the Python GDB scripts that Linux has. It is not 
pleasant to be playing catch when it would have take maybe an extra 
couple hours for someone intimately familiar with the maple tree to come 
up with a suitable implementation replacement for mtree_load().

So having done it felt like there is a maintenance void that needs to be 
filled, hence this patch set.

> 
> I'm actually apposed to the filename you used for the script you want me
> to own.

Is there a different filename that you would prefer?

> 
> I consider myself a low-volume email maintainer and I get enough useless
> emails about apparent trivial fixes that end up causing significant
> damage if they are not dealt with.  So I take care not to sign up for
> more time erosion from meaningful forward progress on tasks I hope to
> have high impact.  I suspect you know that, but I don't know you so I
> don't want to assume.

That seems entirely sane and thanks for being explicit about it.

> 
> Is there anything else you might want to share to entice me to maintain
> this file?  Perhaps there's a documentation pointer that shows how
> useful it is and why I should use it?

It can be as simple as spawning a QEMU instance:

qemu-system-x86_64 \
         -s \
         -cpu "max" \
         -smp 4 \
         -kernel ~/dev/linux/arch/x86/boot/bzImage \
         -device pci-bridge,id=pci_bridge1,bus=pci.0,chassis_nr=1 \
         -drive 
file=debian.img,if=none,id=drive-virtio-disk0,format=qcow2 -device 
virtio-blk-pci,scsi=off,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1 
\
         -nographic \
         -append "root=/dev/vda1 console=ttyS0,115200 mitigations=off" \
         -net nic,model=e1000 -net tap,ifname=tap0

and in another terminal running GDB with:

gdb vmlinux -ex "target remote localhost:1234" -ex "lx-interruptlist"

to obtain a dump of /proc/interrupts which is effectively a replacement 
for iterating over every interrupt descriptor in the system.

> 
> Right now, I have no idea what that file does or how to even check if
> that file works today, so I cannot sign on to maintain it.
> 
> If you want to depend on APIs, this should probably be generated in a
> way that enables updates.  And if that's the case, then why even have a
> file at all and just generate it when needed?  Or, at least, half
> generated and finished by hand?

As it stands today that is not happening, there is zero coordination and 
people who care about GDB scripts just play catch up. But you raise a 
good point, if we are to do that, then we should be able to target 
C/Rust/Python/whatever, that seems like a bigger undertaking and I am 
not clear whether the kernel community as a whole is looking for 
transitioning over to something like this.

> 
> Maybe this is the case but scripts/gdb doesn't have any documentation in
> there, there's no Documentation/scripts or Documentation/gdb either.
> 
> Can you please include more details on the uses of these files?  Failing
> that, perhaps you could point to any documentation?

See the two commands above, those should give you a good environment to 
play with the various GDB scripts which are all prefix with "lx-".

Thanks!
-- 
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c66deb8f-774e-4981-accf-4f507943e08c%40broadcom.com.
