Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBAG4WPGAMGQEMXVQREQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id oCfdGQLujGmSvgAAu9opvQ
	(envelope-from <kasan-dev+bncBC3ZPIWN3EFBBAG4WPGAMGQEMXVQREQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Feb 2026 22:00:50 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 106D612793A
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Feb 2026 22:00:49 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-435aadfaf4esf4007089f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Feb 2026 13:00:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770843649; cv=pass;
        d=google.com; s=arc-20240605;
        b=HezD9htQDouTc52N6WQY1H4voV5jdz6bxLDP6rAZcz1bej8dT837oF9iLjRs1J01j0
         my2NFjEhL3ummEmcNabFy5HGWTLsavefOoZgNh207Ml9nuRtKoFSLpnC+wl5qTnnIKff
         VNqMaSSuU71bby9o3UrPwqj1h0GJwXfHMmBNKBlMGJfhBuTwEu1ZLXE+YmaX925afukb
         dt69Ow2BEDbCaLsUK+RWD7lDt95LkEKcTtZNbZQVE+aGJSE89/JyF/3HpQXTuUo5mVlt
         KbqxsYCL9XEebxZWA8WaeXaAwGqoDpYvPlwbIQRnW9tG+KmV+a6AQ0ErLLkolQgqdVzg
         wAag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=g8E9YHVhTK8E52uVfhA9eC031E7adBTWYfkTVWptNG8=;
        fh=/BMURfe+SXp+1g9kNd9/f+cIvdfJdI1SwupHxcYFikY=;
        b=RMlTOl3F4zpUnefPgk2POHa4c7X4CfKpB15m4ZKbAkO28KNsl+aXv+WZ+TDhmIaOBA
         2hZiI48zfKCY+ucFohf0ex6ZAzV5jnsFvG+FoCrkDT3N3xxkZZj0tDanxbpALO2nyeiy
         uObt1UbPok5hgZ2xDx+vsIYbBD4uK62uxopjL8oCJG5ZuE0eBVzKHp+wmEi6ZqgUTY5t
         R16uU8lXtIh5C13wyurfBIBOO41YciHQQ0bPfbMp8rMZwfqswx0lkOnWlemwi0bVrfUK
         ag7qvwVBBIJWwmMFlwmNpB7tT9fRzjsTqu9PW8McmTPpCN7Yizxqsut7dHyi8/4lzq6c
         AlbQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b="WbsG/Td0";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770843649; x=1771448449; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g8E9YHVhTK8E52uVfhA9eC031E7adBTWYfkTVWptNG8=;
        b=IByx7lECzmSKn2TJgvuXcCQXj7+nXyxXORHVAyQRMLsvDcS92lHZgS2Edzb7KQpvB0
         ZNYL/kJxRrdbm+kJaTQLr9rWvH/Kog0FD2Kd52wugxDvS+CHkFWtBNxZi0E5hyUYXYVx
         v0xPPaSkc+mnlafyv6vwWQbkGKbrqvveWhSwfSYMFax8w+khpUiTCM3AIRNMJsqdfqQB
         r32XkZm76+U8+vZkXFtKbPCnsFHWVpNxfGKjxayGCk47pTpMBcoO7uIHbZ3P/7nwDvs2
         d8s/dAWhrozpMqhp8EXOk020yZFODcr+Cb2u4N6QziG6Xip2tuqoyuT1qYu7NvlQyToC
         hVpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770843649; x=1771448449;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g8E9YHVhTK8E52uVfhA9eC031E7adBTWYfkTVWptNG8=;
        b=q7mXavn4l3feh/ZqcOb2IUTnLYuv7AY12CnSi4TZxwtcOkVXc6CpCzD3tdm5jtwWSB
         PYvcFFgZvoCUdtT56yp4Q+WTibyPJV4xxACWLCCljHN0N9Yol1Bi69dcfLSDh0ocaIoa
         YK1Nc2jCyop2o/Ep8gDY+XIbEnK7vu/0ZVcPCFWc6lneyf65blX+kdK9KWPZyLDEBWEo
         TiWcXs4KKzeYaqcONAoK/QgaIc7iUqSULGZzGrj26lcruRnKLS+R2CVB8meg/+PhHzCc
         VqNJhGJivW2lamfq6WJk/q/KU9QXURgkw9/91RhbdjerGTBxJINVWRNwUAD2Eb9iaB7a
         YlBg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUbSpfuLpErV42Lft1p8TAiy6XvDxsmUORmQiINBXLGIbMq1+bXYjuERAWxcO9Gv+EneRj/pg==@lfdr.de
X-Gm-Message-State: AOJu0YwLCgRUVsHfbSEWhWk+jzdPfQtZ/RUwhnhF/M/lJlOQ4cLrrPnp
	ckJFTKJww1SM8s7AfF+EImpTgiwge9Kv64JMrx3XwkRFlRt3Nxz1eUMc
X-Received: by 2002:a05:600c:450e:b0:483:612d:7a9a with SMTP id 5b1f17b1804b1-4836560ef77mr7266255e9.0.1770843648776;
        Wed, 11 Feb 2026 13:00:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fn3vpK/0Wa7zWEEbtjoDqHGz484CMRoB3rQpbj3cV6Ow=="
Received: by 2002:a05:600c:45c6:b0:480:7388:e20c with SMTP id
 5b1f17b1804b1-483175937adls56454815e9.1.-pod-prod-01-eu; Wed, 11 Feb 2026
 13:00:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVQui2oflqDmlqbeC1d3F27zVGrqS/le8sKrbXkXM6ImITILomzaVfpFYJN7wlBL41TM5C3RmtMGKI=@googlegroups.com
X-Received: by 2002:a05:600c:8b2e:b0:47a:810f:1d06 with SMTP id 5b1f17b1804b1-483656ae300mr6234505e9.4.1770843646266;
        Wed, 11 Feb 2026 13:00:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770843646; cv=none;
        d=google.com; s=arc-20240605;
        b=VplZ/EQOaFDFVGWLhJARTNES6lLGdZ/TjdkkgDh4GIV9vqZ+MCDNpyZAf0nLPwSN+S
         8agGA2VDq6NWqAIjUr82a7dLkVf471yLwSQydZD5kDdxZh84CQTa8zAI7MFJv1Whn9Zi
         XHY44459zZspGQPakTFP0P1vKFCO8nkrdTm86OdysCYdmmmI2+CSRtDP2i8SshI4ZrrB
         AM3VCHOdEJD69r3dXF+3DphGIr4clQ1SdqcavlgcnPw4AFo9nJnvWK3nB0HsCV4inJYz
         /EfB56vHRipcT20FoHoloki4HBEe0Qx+fxxTGn5CVqbRpMJW3GFwsuM1JGUDcPCUbkAp
         bwYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kmPNGhBwlwO4FVQHMiE4wfiI7ZZckEAKXsqDBMMYUlg=;
        fh=0meJ/j3Hbs2+JGfaCnvwyk5URpGBB7AxuDSffBBvors=;
        b=B3gliFu49M/JtxcO0ChIlUCsYUz4aj+bN+bDoe3WsZ4peRchibZrO2Zx1wr4GXC9bQ
         DUyDUMVLpQpnQyBGSk5QkYM+lSAiHXtU1y7tDYu+qls1CqkmB1VfthHTaMVJh+rz25FN
         k/3TvZE68n5mHhvGgOpDsJGPqsXhQEK7oCoXFZDn0X+sJMby5xE7lxYcn6W5vu/yqzum
         TqdRDlkpNJCypZWOSXjcKDfvMZAmj0Uo9Cqb0JB8+YIujR9WB2r4Tj910KeHDKNUPfbK
         AhWTP78Jpg/uWUgc0/da3cgHBXOYbdfmy5+te9kf5GOtsEmFlUps2ocIV5rdowkHh87D
         vOXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b="WbsG/Td0";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x544.google.com (mail-ed1-x544.google.com. [2a00:1450:4864:20::544])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4835ba14c3fsi224725e9.3.2026.02.11.13.00.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Feb 2026 13:00:46 -0800 (PST)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::544 as permitted sender) client-ip=2a00:1450:4864:20::544;
Received: by mail-ed1-x544.google.com with SMTP id 4fb4d7f45d1cf-65a3527c5easo2477711a12.0
        for <kasan-dev@googlegroups.com>; Wed, 11 Feb 2026 13:00:46 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX9D/t7n9Bk55zX3zii6TDzIzn3Y4CvcqXpm3drwQDi26yTxvaK0SRqLIAhcbO8m9AtklnkxkEff1w=@googlegroups.com
X-Gm-Gg: AZuq6aL4oruGj412uEpG/MsI7RBpvvN6o0nPRltSPxmAM8wkw1rUULfU+/DL4mcn/N9
	6ZUarySjOlba/pCyftBFjylnkU5XqE+lnxXcNn6x4EKBBJHZ+byzJMQyIFV/pttmhf9BXsB/im4
	uxjnLEMgQzFjo1+BM98mb4JrghLr13roaGNib6e9Cs9H2p7JbwzwcbtxZBNfMbVgK3S/3LoamiL
	dbtND8+8RKrSLz89wCeB0VHToP+CY70itiMxp0Vd6IKaHivUh8fvER7Qtv+Jninmt9JUin0Jr1s
	JRDqdVvf3gvJU1zL66r5ON5pvvTCAgckjlNCxitsfmH0iBz9Ahfe2IpuYAVQXKn0SbRh/tgfnBn
	2YukuI8P7QSQLdKJVdpqQ3VDC+lWlKjVq0obDGvrOr8z2deZzXnUCcoyEt7VOytkUgzDJXLIUtA
	pLftTE3gzRqAqtGvjJfeGUzW+7iZeTi4NLPWMRrgH/P7cUolwb/vb4G2QIY3wUC/1rE50s8kju
X-Received: by 2002:a05:6402:13cc:b0:659:4d41:9f70 with SMTP id 4fb4d7f45d1cf-65b96e20a5dmr329582a12.30.1770843645570;
        Wed, 11 Feb 2026 13:00:45 -0800 (PST)
Received: from mail-ed1-f51.google.com (mail-ed1-f51.google.com. [209.85.208.51])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-65a3cf45a3bsm1141216a12.25.2026.02.11.13.00.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Feb 2026 13:00:33 -0800 (PST)
Received: by mail-ed1-f51.google.com with SMTP id 4fb4d7f45d1cf-65a40f3f048so1892131a12.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Feb 2026 13:00:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV2cJ849op1D6EZXreEGlINEbkB6/FGIpdDz6ZjjAhrwjsBFyPf0IfDlL0+FvAcaNifXgYd4TOKrW4=@googlegroups.com
X-Received: by 2002:a05:6402:34d1:b0:64b:3225:b771 with SMTP id
 4fb4d7f45d1cf-65b96d602d6mr347433a12.6.1770843620374; Wed, 11 Feb 2026
 13:00:20 -0800 (PST)
MIME-Version: 1.0
References: <20260201192234.380608594@kernel.org> <20260201192835.032221009@kernel.org>
 <aYrewLd7QNiPUJT1@shinmob> <873438c1zc.ffs@tglx> <aYsZrixn9b6s_2zL@shinmob>
 <87wm0kafk2.ffs@tglx> <aYtE2xHG2A8DWWmD@shinmob> <87tsvoa7to.ffs@tglx>
In-Reply-To: <87tsvoa7to.ffs@tglx>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Wed, 11 Feb 2026 13:00:03 -0800
X-Gmail-Original-Message-ID: <CAHk-=whCO2NY8feJ7ueh6oPcoDUNqKGU81M_+LZH9JMUgfBnmw@mail.gmail.com>
X-Gm-Features: AZwV_Qhe7VoumdefwauRwWfhG5SGz7m48nxHOhsq0CrHlq7kPFMdvFN7nLMZzH8
Message-ID: <CAHk-=whCO2NY8feJ7ueh6oPcoDUNqKGU81M_+LZH9JMUgfBnmw@mail.gmail.com>
Subject: Re: [PATCH] sched/mmcid: Don't assume CID is CPU owned on mode switch
To: Thomas Gleixner <tglx@kernel.org>
Cc: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>, LKML <linux-kernel@vger.kernel.org>, 
	Ihor Solodrai <ihor.solodrai@linux.dev>, Shrikanth Hegde <sshegde@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Michael Jeanson <mjeanson@efficios.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b="WbsG/Td0";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.21 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC3ZPIWN3EFBBAG4WPGAMGQEMXVQREQ];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[linux-foundation.org];
	MIME_TRACE(0.00)[0:+];
	TO_DN_EQ_ADDR_SOME(0.00)[];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[wdc.com,vger.kernel.org,linux.dev,linux.ibm.com,infradead.org,efficios.com,gmail.com,google.com,googlegroups.com];
	MISSING_XM_UA(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[11];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[torvalds@linux-foundation.org,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 106D612793A
X-Rspamd-Action: no action

On Tue, 10 Feb 2026 at 08:21, Thomas Gleixner <tglx@kernel.org> wrote:
>
> Linus, can you please take that directly?

Done. Thanks,

                    Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwhCO2NY8feJ7ueh6oPcoDUNqKGU81M_%2BLZH9JMUgfBnmw%40mail.gmail.com.
