Return-Path: <kasan-dev+bncBDJPLAN63YNBBL7JVLGQMGQE6AUM4RQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id MOVqB7O0qml9VgEAu9opvQ
	(envelope-from <kasan-dev+bncBDJPLAN63YNBBL7JVLGQMGQE6AUM4RQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 12:04:19 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x123d.google.com (mail-dl1-x123d.google.com [IPv6:2607:f8b0:4864:20::123d])
	by mail.lfdr.de (Postfix) with ESMTPS id 99D9721F698
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 12:04:18 +0100 (CET)
Received: by mail-dl1-x123d.google.com with SMTP id a92af1059eb24-127876be621sf5163373c88.1
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 03:04:18 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772795056; cv=pass;
        d=google.com; s=arc-20240605;
        b=WUJhgvlah29B28LFA0dlHQVfGGfNfznXnfAE14iT66aMBQ9ZFPcLPicvs49jlklX6m
         6mqlsndN9Laxqq9kTpWF5wYlcaOPS0NZOSFYHBNs0SIHkVEuOwOSry5HIulYyDD9GVWU
         cRN5sSa3LA9Z+kokwB6YDGMQ4NAOhJYmxJcjWEjl+DQInVbBszbitRkTWOdPJBOAlkLD
         U22dbRxDODpMF0g89IHa3A69c35wseU/nzUTbLVRg8/1hPZrkOWnPlHe6d9lt86suoPv
         aS1xg3NrV1jkVjfwjCy433CupBDcBnMVGCmyXLIlQdjxRFdNe87EwlM9YrC6jOcaMPSH
         LFzw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=gc94SblWEgtaPse5kijjdoEsHwzc5YbhR3jtNKtO4Sg=;
        fh=gDAB1Fsl6SEVMXel7oLZX9jpqXbQl7M3cwHTPxdhKqM=;
        b=CAyfw20vHi/i+fA9H4kyE+zPHtFX7qKSn8fShK3MjpcjTFVvJNfqYsBXWWZOrU3bip
         QEL4hHMCXLSJu3nTBaiAtfKKtXillEdHNl+FpgUhE7u/3JcL76f9i2oMl8wDA5hPfrEt
         1KF0j4nzu+voG55yUE6D647YLXPZwY31KoP27CFUy14abLm7AicdJYp1ZOKmnfux/iG0
         B/7I1Frni8gdB36Zat5CHMKivpSmhBc7ZETQ5PTMWfD90BdJ+w1wUe0qQIiCDWzmO/bk
         pRKnuEinnnn2AqSIkeRcKulhx5MpjAakLqjzO70zPLdJGB0AL3zmN0NtPRST1GiGsYUR
         mtaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ARADFykP;
       arc=pass (i=1);
       spf=pass (google.com: domain of jiakaipeanut@gmail.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=jiakaipeanut@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772795056; x=1773399856; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gc94SblWEgtaPse5kijjdoEsHwzc5YbhR3jtNKtO4Sg=;
        b=frDtJ3KcP/0c9ASDIQgxRlTRPqVuIs9snKnQTURobdugQ2aMtcJsOzUAm73r6Fc9y7
         e2RO1/LvAY/hv0ZMF46UuN5H84UqziE6ReBAoJoaUPGTZd59k08yyavRsVqdXQuh+epZ
         JZm5656XqXugrFzoe+TbN0a5yHdikXVIzrvN1iSz1bAyFfRD4c4PeMvmHglbDCWFyJ41
         Fg2smOxDXXeaEcroMc0+8S+O394lH4RCLV913htaSC6i7R5pKLi3TU8QFROSwkUbHNXX
         OcFQAo/obxiVt0t2hbomadaAdPBpUmUiDyYDfOHzyi40Qyeve50mh07rdiWFgH/7gBIT
         hYew==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1772795056; x=1773399856; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gc94SblWEgtaPse5kijjdoEsHwzc5YbhR3jtNKtO4Sg=;
        b=KolnAxPhI7iR32y64aOLpnqz0f49dpAVKagzRYLrF7jQgABa0bFbHAoAbpyvHfUp2Q
         IjeW2MlNGGSt0KP5cveDWEa+I+0pmjnmrSYICenFahvs5/Tk368Zcao/n+saiJH3Kn0C
         0rGm0LOHg3lNP4daC3tf2vosrBJQNu6KPACTbl7RfpsmWsWx28rfAtULNBDueXe1KVLL
         Rks+QPhjD1SpiSRHAbMMDm/u4BHNT1/4x1lsDe94j/3ilrqZP/MsjIYg2dvvPaj8hwMs
         ktTvSsBbq62kChh8kSdo92kmNDOoweHqANiTFMzR9iZuqkVcauxfEIfVi6ruDVwsrvn3
         SGyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772795056; x=1773399856;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gc94SblWEgtaPse5kijjdoEsHwzc5YbhR3jtNKtO4Sg=;
        b=kqcIW+iZjUkJhRuTopIILTV1pGk/7nEaNstYtFCVdqmV2O6yQ9ECnv2H48M6z7Ery2
         MnPDyronPcBQVAoj8ai/aFf2kPx8REk1iL49PZ22h1HJM8g1xky9ZQm3Z8Blsz5waYVe
         LU1B9zukQedFmoBbpMZfT5GNLWW2s2VTWgffE1hbqIHnBTF11EL33SB0A6QG1EaX+SCK
         /ibaQamwbsTzc21lLMZufouToSP1WxWu+e/V//1wy88Y/lr2aLY0h5vBvgzrNL4/hjKP
         8qkTdvi0ntROCj67ByoqvrsX+h57GFrAi5dwW68ZNC6BE5XoUNJcz84KM55EbqtshY1P
         zZuQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWOzkpoJfjFFJKPZ60tFE+47w/QfA99TOxKYL/3KAjxPJUkbxiq9X4GLUPU/emk1LvhlLq1og==@lfdr.de
X-Gm-Message-State: AOJu0YyxrNIfShE4QGw34+3BXvXgOzFiND3HUAdsd/qsTb4hhkpolDhe
	/dngH32dyyn38RzubegnVt31cSnYK/ZavDi5qgzElE2Va639RZKoDwmV
X-Received: by 2002:a05:7022:2208:b0:123:3c65:d724 with SMTP id a92af1059eb24-128bc030d6fmr1698183c88.25.1772795056387;
        Fri, 06 Mar 2026 03:04:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hy5ONYUv7yQ68S1jruY1DUkDINIjD7JXfO0Dz4BlbACg=="
Received: by 2002:a05:701b:4181:10b0:127:36a2:82ac with SMTP id
 a92af1059eb24-128baf8e8d6ls691778c88.0.-pod-prod-00-us; Fri, 06 Mar 2026
 03:04:15 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCX3ZumYurSI8VScENxlm9SRD0w844s4rw5IhRhlUZHiq94uHJxD6JvU3YxzL0kW3OdWD/ga788BC70=@googlegroups.com
X-Received: by 2002:a05:7022:6082:b0:123:3a91:f563 with SMTP id a92af1059eb24-128bbf8319fmr2246112c88.8.1772795054748;
        Fri, 06 Mar 2026 03:04:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772795054; cv=pass;
        d=google.com; s=arc-20240605;
        b=ee/JT2VCBbv5+X20Yk0p1LSkwGV9Q3Ekwb4CRg+DPaG6rKE4cl1F3IkN6jQ8w4R6p7
         na4GLfl3xEKX5o8wBr/kLUWJprewLXDFHyBP1mvrHTk96rLJkBogt1hwDvdAdoFtUjqn
         6WUwXGCAcF2rlcrkFiue5kPHoQisUUtJotgoSIoNUdiAiIUitPeIeEp+DPjx8oyW0mbC
         n4EjRzIvetYG2VMdApEHyfEXP2Lk1qh1XlMcaMNl2Q2CB5EeDSlOKB/s79FlE0VpugkA
         D0aKTjpNn9dwIjf9vxM939E/Kd7lKFG/srVduiaRqwZjTzPCDbcPW7nbJcey8kDRvgkT
         FGeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4FBAY7Ptj233wihUnQns1LO/raURJqSuY43ghIQW2sU=;
        fh=mxmV5NFP1VCSKT20Z3k3QfIZB6b5M9yLmJAAnA6AdRg=;
        b=U6VjD9gXcLGv9WZai5SZ7FDc08TnP8WiwRyr9S3f+czOkUDyJBN1I0zcoHP0KhPXT+
         JZEoKxZw4ckIFuZUWlAvaoQ7Gbi+Fs792ANEAxQvQZLwEHvKfNGL05+0pTqXKMw5eylv
         qQ7ielmmTNz/S+0MKTfht4Ehe2WdCDi4L8Y9EvLIorSh/FdY9Pbb6Skh/NxN9rTWT/yU
         ZZXw+d89BJV5qg/OqdFKJe+HGGCYj9CPbiL+rxQBRleIDtHqnqRRf5P7L+OYhxdU3Wq5
         I4u64t7/vLSUjXKonkKZpqi3hcuOcfjsfTI8sYCjXSuIvzN4PSPnaUMZhaHQVkRaIyDE
         goQQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ARADFykP;
       arc=pass (i=1);
       spf=pass (google.com: domain of jiakaipeanut@gmail.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=jiakaipeanut@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oi1-x22d.google.com (mail-oi1-x22d.google.com. [2607:f8b0:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-128c3bf0900si30247c88.0.2026.03.06.03.04.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2026 03:04:14 -0800 (PST)
Received-SPF: pass (google.com: domain of jiakaipeanut@gmail.com designates 2607:f8b0:4864:20::22d as permitted sender) client-ip=2607:f8b0:4864:20::22d;
Received: by mail-oi1-x22d.google.com with SMTP id 5614622812f47-464ba2bb3aeso6711445b6e.1
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2026 03:04:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772795054; cv=none;
        d=google.com; s=arc-20240605;
        b=If2oww7+APVoNrW4S1YEt4lyAtLZHqwWcElY8ygCDpAJwfwHqYPPcbnRi8d4tNfD2N
         tkVH+XAJr3rHfD4DRo86FmKvnnoqR3h+prYnOZc9ocsuqxCNhP05CPeqfyPC+gHggJZM
         bNzTEvt+6vHfS83fq2aGhplwV8ECqdtEQ8MvzW65ONaZHDDjActCW3dNBeOqNAQD1kMf
         C7iA7orf5klloXo3L7UsGveDCfBT8JQFMKic7zACDsiKBRudMJ8JOoGLMvcIVd0n7Jmo
         eaubyQgcPOEwTCqedTM4WChxjVW/e0sG4ob+4jJPzZQbb8uE3H9NtAHrfUhvTheUKp0C
         666w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4FBAY7Ptj233wihUnQns1LO/raURJqSuY43ghIQW2sU=;
        fh=mxmV5NFP1VCSKT20Z3k3QfIZB6b5M9yLmJAAnA6AdRg=;
        b=Kz7ASs0j3m7FG1PiD4gRpZF4lvHgZt7gao9KkiJwAKI81Pr17xfvVqizAlMLyGPsqC
         grTg/EWpohuuSVAwzsHOKI+2eZqbuXJYuya9CLtSQF2mPwvYeEobkNjhZfyJYh9b6+h9
         f4mQarE7aZQcCDqQlkrgprkCh3ZN/jzzkLJIkdfMUNRUYLS7UIVDWQL9RLQVqsqHQ0VG
         DvgQiU2rOeYCb6zk/cYFvgFbYw3qq5jxcz00aeq/hzbqP6pPShazRrt1oSmh5E4EIhp6
         34jWrYrsABFKbqrnGaI8kv0sGbgsNhULxY6FRCIyxPSjno6AYfFGLiS5Tyy1QFL9ZVAa
         sDsA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXIxCESTe1yROepXEYtalMqXR26X3Lyl5SyloS6BSu+N8CVyAiiOkJqvfzMJ8Y8HArR7ECtPzljcGA=@googlegroups.com
X-Gm-Gg: ATEYQzxzn4DAse4d/BHY4pkc7zq+13HrQOCM6z7/Q4lpO7YKKj5Iea0FzgrOLvweiwe
	D3t5zyxOiC7uVs6pvZ2y8LrRJhwfkT0MHXeq8EyZKbSWcHINzjNci8i0DcF2qkpUlqisp1UAc6z
	i2UYP3zeGhrtMCZoidQXpR3ltNwM2WODqYieqcH+73hrCKOtIvWipCSwO0D8JuqbFKjjIwEAdXN
	egkD1FDnuy2Oztp35ouhxNUHwaH+wnzlSr3t85VgCHG292OMwsMK/IeuxyR5f5CQLwpE3oSMMaC
	eVfgcxU9KMJr+qNZcdCXR9SyGJbMWg9r8Bw6yc8=
X-Received: by 2002:a05:6808:1522:b0:450:b87b:1ec4 with SMTP id
 5614622812f47-466dd0f715bmr888114b6e.15.1772795053874; Fri, 06 Mar 2026
 03:04:13 -0800 (PST)
MIME-Version: 1.0
References: <20260112192827.25989-4-ethan.w.s.graham@gmail.com>
 <20260306094459.973-1-jiakaiPeanut@gmail.com> <CANgxf6yMNZ3=xm9xVhPZDuxMc__7pQk=mti-CyD1QjUOgTJLEA@mail.gmail.com>
In-Reply-To: <CANgxf6yMNZ3=xm9xVhPZDuxMc__7pQk=mti-CyD1QjUOgTJLEA@mail.gmail.com>
From: Jiakai Xu <jiakaipeanut@gmail.com>
Date: Fri, 6 Mar 2026 19:04:02 +0800
X-Gm-Features: AaiRm50fj2zUudpYSke1Ww9X_50G4gGf4UxVg0WDage5_ANMvrcVMJxjNhrQX6Q
Message-ID: <CAFb8wJvmnPv96o9Kr9VAh=cL9zMr8-5eCEmmkjtgX02_Ypa4nw@mail.gmail.com>
Subject: Re: Question about "stateless or low-state functions" in KFuzzTest doc
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, andy.shevchenko@gmail.com, 
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, ebiggers@kernel.org, elver@google.com, glider@google.com, 
	gregkh@linuxfoundation.org, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, mcgrof@kernel.org, rmoar@google.com, 
	shuah@kernel.org, sj@kernel.org, skhan@linuxfoundation.org, 
	tarasmadan@google.com, wentaoz5@illinois.edu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jiakaipeanut@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ARADFykP;       arc=pass
 (i=1);       spf=pass (google.com: domain of jiakaipeanut@gmail.com
 designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=jiakaipeanut@gmail.com;
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
X-Rspamd-Queue-Id: 99D9721F698
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBDJPLAN63YNBBL7JVLGQMGQE6AUM4RQ];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[gmail.com];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[34];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	FREEMAIL_FROM(0.00)[gmail.com];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	NEURAL_HAM(-0.00)[-0.997];
	FROM_NEQ_ENVFROM(0.00)[jiakaipeanut@gmail.com,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,kernel.org,linux.dev,davemloft.net,google.com,redhat.com,linuxfoundation.org,gondor.apana.org.au,cloudflare.com,suse.cz,sipsolutions.net,googlegroups.com,vger.kernel.org,kvack.org,wunner.de,illinois.edu];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[]
X-Rspamd-Action: no action

Hi Ethan,

Thanks for the detailed explanation.

Would it be fair to say that KFuzzTest is not well suited for testing
kernel functions that are heavily influenced by or have a significant
impact on kernel state?

I agree with your point that "the goal of the framework is to fuzz real
functions with realistic inputs." One thing I've been thinking about,
though, is how we determine what counts as "realistic" input for a given
function. If the generated inputs that a function would never actually
receive in practice, we'd likely end up chasing false-positive crashes
that don't represent real bugs.

Thanks,
Jiakai


On Fri, Mar 6, 2026 at 6:29=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmail=
.com> wrote:
>
> On Fri, Mar 6, 2026 at 10:45=E2=80=AFAM Jiakai Xu <jiakaipeanut@gmail.com=
> wrote:
> >
> > Hi Ethan and all,
>
> Hi Jiakai
>
> > I've been reading the KFuzzTest documentation patch (v4 3/6) with great
> > interest. I have some questions about the scope and applicability of th=
is
> > framework that I'd like to discuss with the community.
> >
> > The documentation states:
> > > It is intended for testing stateless or low-state functions that are
> > > difficult to reach from the system call interface, such as routines
> > > involved in file format parsing or complex data transformations.
> >
> > I'm trying to better understand what qualifies as a "stateless or
> > low-state function" in the kernel context. How do we define or identify
> > whether a kernel function is stateless or low-state?
> >
> > Also, I'm curious - what proportion of kernel functions would we
> > estimate falls into this category?
>
> I would define it based on "practical heuristics". A function is probably=
 a
> good candidate for KFuzzTest if it fits these loose criteria:
>
> - Minimal setup: KFuzzTest currently supports blob-based fuzzing, so the
>   function should consume raw data (or a thin wrapper struct) and not
>   require a complex web of pre-initialized objects or deep call-chain
>   prerequisites.
> - Manageable teardown: if the function allocates memory or creates
>   objects, the fuzzing harness must be able to cleanly free or revert
>   that state before the next iteration. An example of this can be found
>   in the pkcs7 example in patch 5/6 [1].
> - Non-destructive global impact: it's okay if the function touches global
>   state in minor ways (e.g., writing to the OID registry logs as is done
>   by the crypto/ functions that are fuzzed by the harnesses in patch 5/6)=
,
>   but what matters is that the kernel isn't left in a broken state before=
 the
>   next fuzzing iteration, meaning no leaked global locks, no corrupted
>   shared data structures, and no deadlocks.
>
> These loose criteria are just suggestions, as you can technically fuzz
> anything that you want to - KFuzzTest won't stop you. The danger is
> that the kernel isn't designed to have raw userspace inputs shoved
> into deep stateful functions out of nowhere. If a harness or function
> relies on complex ad-hoc state management or strict preconditions,
> fuzzing it out of context will likely just result in false positives, pan=
ics,
> and ultimately bogus harnesses.
>
> The goal of the framework is to fuzz real functions with realistic inputs
> without accidentally breaking other parts of the kernel that the function
> wasn't meant to touch. Therefore ideal targets (like the PKCS7 example)
> are ones with minimal setup (just passing a blob), have manageable
> teardown (like freeing a returned object on success) and don't
> destructively impact global state (even if they do minor things like
> printing to logs).
>
> That said, I'm curious to see what you come up with! I'm sure there are
> other use cases that I haven't thought of.
>
> [1] PKCS7 message parser fuzzing harness:
> https://lore.kernel.org/all/20260112192827.25989-6-ethan.w.s.graham@gmail=
.com/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AFb8wJvmnPv96o9Kr9VAh%3DcL9zMr8-5eCEmmkjtgX02_Ypa4nw%40mail.gmail.com.
