Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBIPOQHGAMGQEHTMUK5I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id eMjVByR3gGmo8gIAu9opvQ
	(envelope-from <kasan-dev+bncBDM2ZIVFZQPBBIPOQHGAMGQEHTMUK5I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Feb 2026 11:06:28 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 83101CA7A0
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Feb 2026 11:06:27 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-43284f60a8asf3462224f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Feb 2026 02:06:27 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1770026787; cv=pass;
        d=google.com; s=arc-20240605;
        b=UbdIJI91/BQZNJP98yj8xhGItFyOHpGmnf8+CdQpVs4vtqA4PmjTeR+Nuleui+TutN
         VzaWB3pURCZ5GWfT545qgKWviOVQN4TMGZUmpZLmU27QcfCF+2Ortl91BbqBnHtjygm5
         THRVFnvzdeGFkv0fJWDBvXfcR5kd8g/vnLUIgm7l66n70vDtU7hC+saS54cf9chkIKls
         KR4F9UtTy+mBQETUZ+FHxesluYyT2v/wCbOlggmipntZQLdxdBCw887vWZ2bdyFbB2vN
         +LavtdHbEnatd9x8/z94My23w30PPorjoLBec25vlQ9zx4RyaYxK1/Gb8nfBPPN9mzx4
         Vf8Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=OP5TxPnn7BqgukoTVEMfivmMnw/ztNiqYEqaRn46TgE=;
        fh=HQc5naiIW6pCo7ayHDTCwNiHDvjUlOWzf3skaZGuQsg=;
        b=eKq3x2X5p4hknuoDvZRY9UaJh78ZgkDNBiqXHVC9UH2BEqGgnRKh9QwQj5/6f4zyFI
         iO1gFODKQGLVMvTpTODjx+TuYlQlv1a4n8fzGagJD4Xbn5hIO17MKrtF74AF92KVEoqH
         SngVinfQjxEzv/hTAe+lMcJHgB4VrHyLxzr81WEJuuDDwShjlAHrRdsWvNc9XBn/7Boq
         lqnHBYLg5SBSfiEjuScFyz+lFs42tiSKKpCehbKUBcSiTGDDME5ziuDI23ztcegxBlLM
         1dHUfxODoUhRrJ1iEJ7FqVba//XTcksG1Yg7/L0MIYTE4TIF0mpxZZuebhw4KKRJsZj8
         1BQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Sh06nvif;
       arc=pass (i=1);
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770026787; x=1770631587; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OP5TxPnn7BqgukoTVEMfivmMnw/ztNiqYEqaRn46TgE=;
        b=Spm3xGboSS+BYEN47xXOGXtQxncRwTwlV4damJ8HBKd80MNedL3P4Sxr+7hZAL4LRh
         Pm862dFY/jc+Z8HCmAwKvUggX5v/x4Bx5HiNArViP4/mVoSmNk02Tb8vD+6ujs176GYI
         Q3UBl1QOotloG5zQdvdkn6C48zui1W3uHJ0obB0GFLoNymYEzx4cC5Gj3RK883/n13r9
         eZANgfVH4esSGE5CUOMHYA603Ez6YISQd7CxN1UGK9UXnVGxLVmkGmvrnuPlTztaVW1+
         qb0HmZx7ED8qzSjgPITH6hQVb7lhveqOqiUIoxK9NvqPjEgHmH1+OZYQe2P2IL6ek6dx
         +1GQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1770026787; x=1770631587; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=OP5TxPnn7BqgukoTVEMfivmMnw/ztNiqYEqaRn46TgE=;
        b=m3QEeqhaXzvLdyOeMAirBfGY6B7yscNkcVG7XhjWQSwjVGm3HJ1CU9i42u58JKI5A/
         E08EjW85U/YsQkaYQZh2klxKjfUngQxLsy0idFwHb5KnnnTBIZZ+79phCr8w8CqP422L
         lT+UbChMZxtQDeFE+UtzQRabIDdVFqSGNJbA2qvtdLM9xsihbNdMW5GPKYio3Hxy7z+g
         vpqhsvF6/09VJ04wW2jnNw4QdZ45Gl6a5WjKlbTPPGeeK+oNyrxX6vHVOmfKAidv2AAl
         zzstITI6NLHznRHXIxYnSFu/m1UHxWjzXtkk5PTHev9cTzIN65hOADowCHZ2w7HNxL/q
         Dfgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770026787; x=1770631587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OP5TxPnn7BqgukoTVEMfivmMnw/ztNiqYEqaRn46TgE=;
        b=dwBjbBrmKQjrKtI/FN+xtANkF4y5ELgjVKPO8L+51jKDZ/xgBQ/e1HdmE0G+vGe5cT
         tsT7luBT9IIRfgygolarEuL0oAu6U7PSFVCMFhtd72xVF+XFgXvtCagTSNq6IY9ZVotV
         CytjaBfDSepXRZCfp6qfEcfxbACsbjem0W+ekGEpf+1UBYmC7vDP6Qo7NOuXkCi9ahUR
         Jm0b/FpQkTYhwFF9LvmiIc1lJgvV/h0FeBUgoTKaAH2Wy6Grk9YpscIbrV/PEqorz4No
         VLdwdaY0vwgM5LWZ4YvcBXBLHFqJf8mQDZGq1TPzq0C7ymMOqcenQgnhZYWZuh9yWrqE
         tfCA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWXkinc5VsdIrqFiMf4HeCMGDySM7Q6UWeW4xaUPaD8xMgEuHmkn0BDRCID/tgfnqWgojQfyA==@lfdr.de
X-Gm-Message-State: AOJu0YwlNGVPmNjSp25JNLypUE4uOcEq1JDo5oPUxvDe+KCxxKHlz4FJ
	ABefuzDNjCM2FgVnRdpRGRv852SOs41ldzF2z+QW0BsWRgDTG/fPDNZm
X-Received: by 2002:a05:6000:2dc2:b0:435:a815:dd8d with SMTP id ffacd0b85a97d-435f3aba09emr14145849f8f.55.1770026786218;
        Mon, 02 Feb 2026 02:06:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hdu81PCrQ1uBSTptmT9B5gVhk9Lf3yXwOqCH8Bof02Cw=="
Received: by 2002:a05:6000:40e0:b0:432:84f4:e9e2 with SMTP id
 ffacd0b85a97d-435fc90f1b6ls1152020f8f.1.-pod-prod-03-eu; Mon, 02 Feb 2026
 02:06:23 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVWH8A0nqXchQR2p+fY6qcJ/aZNM41IQN5DwuOIVAQvFqa724/65wEoFTVQM+pLQLSyStFHyp0XX9I=@googlegroups.com
X-Received: by 2002:a5d:64e6:0:b0:431:488:b9b4 with SMTP id ffacd0b85a97d-435f3a7e627mr16133784f8f.17.1770026783155;
        Mon, 02 Feb 2026 02:06:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770026783; cv=pass;
        d=google.com; s=arc-20240605;
        b=FLBc9TqsA/qPj1raNAsdiC/xCoiBtkJSLiAYIdkIITjgFaB1VLGb6FMXr4I01lp4hH
         sid4x/0F8K87BMqUU8+eOMl25fLa6FoKMLrvEq9zpWaiDj9gRBuZ+AWGLariCVPm0gEc
         oh7L/8HaoRmqwJSGEJlrD94EYGrZGNBNvogGkgNM/mFoK1DXecaGX493uAVZ44npRrFa
         2COXqPgkJjKHgFQwYYYiMsVG1ndpkAfI6tGOrt0+EsVCoQ3cS2mKn4KLVyht7WXNAr7+
         4GjgrHJyLPlvkTP2P+WSxWS+8BQGrgSspwjieAtWX6i5PauOJPbtYARYE02D2neie4R8
         YIOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=+sujZpRcXN3Ea62MSKZHPOicvhWtNxm4y5+j4D1I4yM=;
        fh=Mol6lm79xRpDDizojtY0uQvMgbDhwY7mYxc8+5MPUAI=;
        b=IqgyYKz+7xtSryR+YIbBG1Q2TXDUvqHZdi6KMFLTqTdMsH/BJMLVO3K0kNobWVTlm+
         cQIATufOzTVblkjNn7/G0kmVr5/rnzYtO+pvJtwzJBs4QbFj8hc+T50sMEFPTGRNDPAu
         WFvhKklnLq152NwxZTSYQBpT31/xaUnlefv5xM1iQL3Gfci93kEEdQuLQWu9symYWL2E
         cli1921EyH06A4knqNtxOjIOLFpVQ3qUYVOAdGz1LL7VwwrbUmoIC3nMBV8EI5uGok5F
         PoyN/h2zkJGXouL5cOfSQOgXosRri90/pkoJnIAwYgotHN3YobnbsmXrQb6+SND9T58o
         lmLw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Sh06nvif;
       arc=pass (i=1);
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435e10f9367si326451f8f.4.2026.02.02.02.06.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Feb 2026 02:06:23 -0800 (PST)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id 4fb4d7f45d1cf-6505cac9879so6252785a12.1
        for <kasan-dev@googlegroups.com>; Mon, 02 Feb 2026 02:06:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770026783; cv=none;
        d=google.com; s=arc-20240605;
        b=X+uOU8pmX2C85pkaT9GUK9F/+m5tsrhS9AGnh1Q5OrQkchDrQE+9ynA1fChHHlEpHb
         NpLz7BLqbHf0n/KQYaQn8rXwgHFEaQ5skhCfA+rWHIRwUfRDwmNZXmgPz47V/PrbYo6R
         krjm5P5ZePcaQwGN01WabGYqti0tYOrQz2eGC33N27cMCgtMsREFjwH9g5K1pu9KdQsY
         1T6GrXZmanI1P7h3ednX+LIR1A0SjBdR1+jkf40vtEppBBkmg4OpkeL2CJtw+J6ShuFP
         U6a3Oy5OmVct+GnuMzcw691y37VBW4mnnSTaHMuytZoyBv8pw27s8A1OGkgK4AD3YQ0A
         yCRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=+sujZpRcXN3Ea62MSKZHPOicvhWtNxm4y5+j4D1I4yM=;
        fh=Mol6lm79xRpDDizojtY0uQvMgbDhwY7mYxc8+5MPUAI=;
        b=a6/A7EOmoazfzY7EjjHbOi1J7uy8zMLXUVPjROtfaiHHQNH97nLEDEJjlyxqDHY2Ag
         /MOtdYJ80rb1ZTw1uMnr89Hxyngh1P3qVU+LB2K3NnDmxk0QWmAZT842Ki1tzxCsEqEU
         11nJdJSaUCgYBU6J58DuekHKBCdhCNkTBXZdOp1c5BUwl+iH5eY2Us4odRe4e7muvVeJ
         phj3SyPKW966+ViLmV3L1JFSv8NykyzNMUcqKb+hb3QCN7crEjKOrEjw6pKrcv2m0NB5
         y+nK5Z4cZaM4xDjLBXsX93PMl54aymMic4zNPo3spXgnWBak65GK9vyUUPV6dfKwWy0/
         prIw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCValAO221PzZq9HoOkL/RFpLkT69PhN2c5avVANIPlb3lpitrIjUGIaz8mcXZ4SgCyI8rqnFNPAQeg=@googlegroups.com
X-Gm-Gg: AZuq6aKJorICLiCUTTKKy5Se9jctNP1xppb/2As2JslH8FV5q95VZbszXbuGrOZqK6m
	zuxqHqRSO2BJM57ooGv8Y40ufGLbxtNk7rxSjalhqc4nHmA2AaoVR58p6u+MzlcreyzP8MqPfzp
	r4osAWEvDWem2fnr/xtQI1wqXoFT25IxFq2X1HsDA6R4337PDaxkYP2pJ6awufb6Ha2nVpVhS0a
	9KI9KgU2JnDKEajKiSmb9RMZTEGiRBfHpc3RcRXLIzX6s5SAeQ4DuGyXKAN8ZOfEI18Xjr2cY7J
	VOo=
X-Received: by 2002:a05:6402:524a:b0:658:be1c:4136 with SMTP id
 4fb4d7f45d1cf-658de59398bmr6725845a12.26.1770026781637; Mon, 02 Feb 2026
 02:06:21 -0800 (PST)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Mon, 2 Feb 2026 12:06:08 +0200
X-Gm-Features: AZwV_QjzthtaRUpx3BjTRwxVX3XbW6G9t8b4qgeDvMVbBD4SJ3I4yeud6jewn48
Message-ID: <CADj1ZKmJR9av8iWcY9TWX2+JooNCOUOoewKpyXBrJknNDR0B_w@mail.gmail.com>
Subject: =?UTF-8?B?2KjZhdmG2KfYs9io2Kkg2K3ZhNmI2YQg2LTZh9ixINix2YXYttin2YYg2KfZhNmF2KjYpw==?=
	=?UTF-8?B?2LHZgyDZitiz2LHZkdmG2Kcg2KrZgtiv2YrZhSDYrdiy2YXYqSDYp9mE2KjYsdin2YXYrCDYp9mE2LE=?=
	=?UTF-8?B?2YXYttin2YbZitipINin2YTZhdiq2K7Ytdi12Kkg2KfZhNmH2KfYr9mB2Kkg2KXZhNmJINiq2YbZhdmK?=
	=?UTF-8?B?2Kkg2YLYr9ix2KfYqiDZhdmG2LPZiNio2Yog2KfZhNis2YfYp9iqINin2YTYrdmD2YjZhdmK2KnYjCA=?=
	=?UTF-8?B?2YjYqti52LLZitiyINmD2YHYp9ih2KrZh9mFINin2YTZhdmH2YbZitip2Iwg2YjYqtix2LPZitiuINin?=
	=?UTF-8?B?2YTZgtmK2YUg2KfZhNmF2KTYs9iz2YrYqdiMINio2YXYpyDZitmI2KfZg9ioINmF2KrYt9mE2KjYp9iq?=
	=?UTF-8?B?INin2YTYudmF2YQg2KfZhNit2YPZiNmF2Yog2KfZhNit2K/ZitirLiDYsdmF2LbYp9mG4oCmINmB2LE=?=
	=?UTF-8?B?2LXYqSDZhNmE2KrYt9mI2YrYsdiMINmI2KjYr9in2YrYqSDYrNiv2YrYr9ipINmE2YTYqtmF2YrZkdiy?=
	=?UTF-8?B?INin2YTZiNi42YrZgdmKLg==?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000009003700649d479d3"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Sh06nvif;       arc=pass
 (i=1);       spf=pass (google.com: domain of marwaipm1@gmail.com designates
 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [3.85 / 15.00];
	R_UNDISC_RCPT(3.00)[];
	LONG_SUBJ(1.96)[261];
	URI_COUNT_ODD(1.00)[3];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_BASE64_TEXT(0.10)[];
	MIME_GOOD(-0.10)[multipart/alternative,text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+,1:+,2:~];
	RCPT_COUNT_ONE(0.00)[1];
	FREEMAIL_FROM(0.00)[gmail.com];
	TO_DN_ALL(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[marwaipm1@gmail.com,kasan-dev@googlegroups.com];
	TAGGED_FROM(0.00)[bncBDM2ZIVFZQPBBIPOQHGAMGQEHTMUK5I];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	NEURAL_SPAM(0.00)[1.000];
	MISSING_XM_UA(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid]
X-Rspamd-Queue-Id: 83101CA7A0
X-Rspamd-Action: no action

--0000000000009003700649d479d3
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2KjZhdmG2KfYs9io2Kkg2K3ZhNmI2YQg2LTZh9ixINix2YXYttin2YYg2KfZhNmF2KjYp9ix2YMN
Cg0K2YrYs9ix2ZHZhtinINiq2YLYr9mK2YUg2K3YstmF2Kkg2KfZhNio2LHYp9mF2Kwg2KfZhNix
2YXYttin2YbZitipINin2YTZhdiq2K7Ytdi12Kkg2KfZhNmH2KfYr9mB2Kkg2KXZhNmJINiq2YbZ
hdmK2Kkg2YLYr9ix2KfYqiDZhdmG2LPZiNio2YoNCtin2YTYrNmH2KfYqiDYp9mE2K3Zg9mI2YXZ
itip2IwNCg0KICAgICAgICAgICAgICAgICAgICDZiNiq2LnYstmK2LIg2YPZgdin2KHYqtmH2YUg
2KfZhNmF2YfZhtmK2KnYjCDZiNiq2LHYs9mK2K4g2KfZhNmC2YrZhSDYp9mE2YXYpNiz2LPZitip
2Iwg2KjZhdinDQrZitmI2KfZg9ioINmF2KrYt9mE2KjYp9iqINin2YTYudmF2YQg2KfZhNit2YPZ
iNmF2Yog2KfZhNit2K/ZitirLg0KDQrYsdmF2LbYp9mG4oCmINmB2LHYtdipINmE2YTYqti32YjZ
itix2Iwg2YjYqNiv2KfZitipINis2K/Zitiv2Kkg2YTZhNiq2YXZitmR2LIg2KfZhNmI2LjZitmB
2YouDQoNCtij2YfYr9in2YEg2KfZhNio2LHYp9mF2KwNCg0Kw7wgICAgINix2YHYuSDZg9mB2KfY
odipINin2YTYo9iv2KfYoSDYp9mE2YjYuNmK2YHZiiDZiNin2YTZhdik2LPYs9mKDQoNCsO8ICAg
ICDYqti52LLZitiyINin2YTYp9mE2KrYstin2YUg2KfZhNmI2LjZitmB2Yog2YjYo9iu2YTYp9mC
2YrYp9iqINin2YTYrtiv2YXYqSDYp9mE2LnYp9mF2KkNCg0Kw7wgICAgINiq2YbZhdmK2Kkg2KfZ
hNmF2YfYp9ix2KfYqiDYp9mE2KXYr9in2LHZitipINmI2KfZhNiz2YTZiNmD2YrYqQ0KDQrDvCAg
ICAg2KrYrdiz2YrZhiDYrNmI2K/YqSDYp9mE2KrYudin2YXZhCDZhdi5INin2YTZhdiz2KrZgdmK
2K/ZitmGINmI2KfZhNis2YXZh9mI2LENCg0Kw7wgICAgINiv2LnZhSDYp9mE2KrYrdmI2YQg2KfZ
hNix2YLZhdmKINmI2KfZhNmI2LnZiiDYp9mE2KrZgtmG2YoNCg0Kw7wgICAgINiq2YXZg9mK2YYg
2KfZhNmD2YjYp9iv2LEg2YXZhiDYo9iv2YjYp9iqINin2YTYqti32YjZitixINin2YTZhdiz2KrY
r9in2YUNCg0KDQoNCtmF2K3Yp9mI2LEg2KfZhNio2LHYp9mF2Kwg2KfZhNiq2K/YsdmK2KjZitip
DQoNCtin2YTYo9iz2KjZiNi5INin2YTYo9mI2YQgOiDYp9mE2KPYs9in2LPZitin2Kog2KfZhNmF
2YfZhtmK2Kkg2YjYp9mE2YXYpNiz2LPZitipDQoNCjEuICAgICDYpdiv2KfYsdipINin2YTZiNmC
2Kog2YjYp9mE2KfZhNiq2LLYp9mFINin2YTZiNi42YrZgdmKINmB2Yog2KfZhNis2YfYp9iqINin
2YTYrdmD2YjZhdmK2KkNCg0KMi4gICAgINin2YTYs9mE2YjZgyDYp9mE2YjYuNmK2YHZiiDZiNij
2K7ZhNin2YLZitin2Kog2KfZhNiu2K/ZhdipINin2YTYudin2YXYqQ0KDQozLiAgICAg2KXYudiv
2KfYryDYp9mE2KrZgtin2LHZitixINin2YTYpdiv2KfYsdmK2Kkg2KfZhNit2YPZiNmF2YrYqSDY
qNin2K3Yqtix2KfZgQ0KDQo0LiAgICAg2YXZh9in2LHYp9iqINin2YTYqti52KfZhdmEINmF2Lkg
2KfZhNmF2LHYp9is2LnZitmGINmI2KfZhNis2YXZh9mI2LENCg0KNS4gICAgINij2LPYp9iz2YrY
p9iqINin2YTYudmF2YQg2KfZhNmF2KTYs9iz2Yog2YHZiiDYp9mE2YjYstin2LHYp9iqINmI2KfZ
hNmH2YrYptin2KoNCg0K2KfZhNij2LPYqNmI2Lkg2KfZhNir2KfZhtmKOiDYp9mE2K3ZiNmD2YXY
qSDZiNin2YTYo9iv2KfYoSDYp9mE2YjYuNmK2YHZig0KDQoxLiAgICAg2YXYqNin2K/YpiDYp9mE
2K3ZiNmD2YXYqSDZgdmKINin2YTYrNmH2KfYqiDYp9mE2K3Zg9mI2YXZitipICjZhdiv2K7ZhCDZ
hdio2LPYtykNCg0KMi4gICAgINmF2YPYp9mB2K3YqSDYp9mE2YHYs9in2K8g2YjYqti52LLZitiy
INin2YTZhtiy2KfZh9ipINmI2KfZhNin2YTYqtiy2KfZhSDYp9mE2YjYuNmK2YHZig0KDQozLiAg
ICAg2KXYr9in2LHYqSDYp9mE2YXYrtin2LfYsSDYp9mE2YjYuNmK2YHZitipINmB2Yog2KfZhNmC
2LfYp9i5INin2YTYrdmD2YjZhdmKDQoNCjQuICAgICDYqtmC2YrZitmFINin2YTYo9iv2KfYoSDY
p9mE2YjYuNmK2YHZiiDYqNin2LPYqtiu2K/Yp9mFINmF2KTYtNix2KfYqiDZhdio2LPYt9ipIChL
UEkpDQoNCjUuICAgICDYpdiv2KfYsdipINi22LrZiNi3INin2YTYudmF2YQg2YHZiiDYp9mE2YXY
pNiz2LPYp9iqINin2YTYrdmD2YjZhdmK2KkNCg0KDQoNCg0KDQoNCg0K2KfZhNij2LPYqNmI2Lkg
2KfZhNir2KfZhNirOiDYp9mE2KrYt9mI2YrYsSDZiNin2YTYqtit2YjZhCDYp9mE2YXYpNiz2LPZ
ig0KDQoxLiAgICAg2KfZhNiq2K3ZiNmEINin2YTYsdmC2YXZiiDZgdmKINin2YTYudmF2YQg2KfZ
hNit2YPZiNmF2YogKNmF2YHYp9mH2YrZhSDZiNiq2LfYqNmK2YLYp9iqKQ0KDQoyLiAgICAg2KfZ
hNiw2YPYp9ihINin2YTYp9i12LfZhtin2LnZiiDZiNiv2YjYsdmHINmB2Yog2KrYrdiz2YrZhiDY
p9mE2K7Yr9mF2KfYqiDYp9mE2K3Zg9mI2YXZitipDQoNCjMuICAgICDYp9mE2KPZhdmGINin2YTY
s9mK2KjYsdin2YbZiiDZiNin2YTZiNi52Yog2KfZhNmI2LjZitmB2Yog2YTZhdmG2LPZiNio2Yog
2KfZhNis2YfYp9iqINin2YTYrdmD2YjZhdmK2KkNCg0KNC4gICAgINin2YTYp9iq2LXYp9mEINin
2YTYrdmD2YjZhdmKINin2YTZgdi52ZHYp9mEDQoNCjUuICAgICDYp9mE2YXYr9iu2YQg2KfZhNi5
2YXZhNmKINmE2LHZgdi5INmD2YHYp9ih2Kkg2KfZhNmD2YjYp9iv2LEg2KfZhNit2YPZiNmF2YrY
qQ0KDQrYp9mE2YHYptipINin2YTZhdiz2KrZh9iv2YHYqQ0KDQrDvCAgICAg2YXZhtiz2YjYqNmI
INin2YTYrNmH2KfYqiDYp9mE2K3Zg9mI2YXZitipDQoNCsO8ICAgICDYp9mE2YLZitin2K/Yp9iq
INin2YTYpdiv2KfYsdmK2Kkg2YjYp9mE2KXYtNix2KfZgdmK2KkNCg0Kw7wgICAgINix2KTYs9in
2KEg2KfZhNij2YLYs9in2YUg2YjYp9mE2YjYrdiv2KfYqg0KDQrDvCAgICAg2KfZhNmD2YjYp9iv
2LEg2KfZhNil2K/Yp9ix2YrYqSDZiNin2YTZgdmG2YrYqQ0KDQrDvCAgICAg2KfZhNmF2YjYuNmB
2YjZhiDYp9mE2KzYr9ivINio2KfZhNmC2LfYp9i5INin2YTYrdmD2YjZhdmKDQoNCg0KDQrZhdmF
2YrYstin2Kog2KfZhNi52LHYtiDYp9mE2LHZhdi22KfZhtmKDQoNCsO8ICAgICDZhdit2KrZiNmJ
INiq2K/YsdmK2KjZiiDZhdiq2K7Ytdi1INmI2YXYsdiq2KjYtyDYqNin2YTZiNin2YLYuSDYp9mE
2LnZhdmE2YoNCg0Kw7wgICAgINi32LHYrSDZhdio2LPZkdi3INmK2YbYp9iz2Kgg2YXYrtiq2YTZ
gSDYp9mE2YXYs9iq2YjZitin2Kog2KfZhNmI2LjZitmB2YrYqQ0KDQrDvCAgICAg2KjZitim2Kkg
2KrYr9ix2YrYqNmK2Kkg2YXYrdmB2ZHYstipINiu2YTYp9mEINi02YfYsSDYsdmF2LbYp9mGDQoN
CsO8ICAgICDYr9i52YUg2KfZhNiq2LfZiNmK2LEg2KfZhNmI2LjZitmB2Yog2YjYp9mE2YXYpNiz
2LPZig0KDQrDvCAgICAg2LTZh9in2K/YqSDYrdi22YjYsSDZhdi52KrZhdiv2Kkg2KjZhtmH2KfZ
itipINin2YTYqNix2YbYp9mF2KwNCg0KDQoNCg0KDQrYrdiy2YXYqSDYp9mE2KjYsdin2YXYrCDY
p9mE2KrYr9ix2YrYqNmK2Kkg2K7ZhNin2YQg2LTZh9ixINix2YXYttin2YYg2KfZhNmF2KjYp9ix
2YPZgA0KDQrYp9mE2KPYs9io2YjYuSDYp9mE2KPZiNmEICAo2YXZhiDYp9mE2KPYrdivIDIyINmB
2KjYsdin2YrYsSDYpdmE2Ykg2KfZhNiu2YXZitizIDI2INmB2KjYsdin2YrYsSAyMDI2KQ0KDQoq
2YUqDQoNCtin2LPZhSDYp9mE2KjYsdmG2KfZhdisDQoNCtin2YTYqtin2LHZitiuDQoNCioxKg0K
DQrYpdiv2KfYsdipINin2YTZiNmC2Kog2YjYp9mE2KfZhNiq2LLYp9mFINin2YTZiNi42YrZgdmK
INmB2Yog2KfZhNis2YfYp9iqINin2YTYrdmD2YjZhdmK2KkNCg0K2KfZhNij2K3YryAyMiDZgdio
2LHYp9mK2LEgMjAyNg0KDQoqMioNCg0K2KfZhNiz2YTZiNmDINin2YTZiNi42YrZgdmKINmI2KPY
rtmE2KfZgtmK2KfYqiDYp9mE2K7Yr9mF2Kkg2KfZhNi52KfZhdipDQoNCtin2YTYp9ir2YbZitmG
IDIzINmB2KjYsdin2YrYsSAyMDI2DQoNCiozKg0KDQrYpdi52K/Yp9ivINin2YTYqtmC2KfYsdmK
2LEg2KfZhNil2K/Yp9ix2YrYqSDYp9mE2K3Zg9mI2YXZitipINio2KfYrdiq2LHYp9mBDQoNCtin
2YTYq9mE2KfYq9in2KEgMjQg2YHYqNix2KfZitixIDIwMjYNCg0KKjQqDQoNCtmF2YfYp9ix2KfY
qiDYp9mE2KrYudin2YXZhCDZhdi5INin2YTZhdix2KfYrNi52YrZhiDZiNin2YTYrNmF2YfZiNix
DQoNCtin2YTYo9ix2KjYudin2KEgMjUg2YHYqNix2KfZitixIDIwMjYNCg0KKjUqDQoNCtij2LPY
p9iz2YrYp9iqINin2YTYudmF2YQg2KfZhNmF2KTYs9iz2Yog2YHZiiDYp9mE2YjYstin2LHYp9iq
INmI2KfZhNmH2YrYptin2KoNCg0K2KfZhNiu2YXZitizIDI2INmB2KjYsdin2YrYsSAyMDI2DQoN
Ctin2YTYo9iz2KjZiNi5INin2YTYq9in2YbZiiAo2YXZhiDYp9mE2KPYrdivIDEg2YXYp9ix2LMg
2KXZhNmJINin2YTYrtmF2YrYsyA1INmF2KfYsdizIDIwMjYpDQoNCio2Kg0KDQrZhdio2KfYr9im
INin2YTYrdmI2YPZhdipINmB2Yog2KfZhNis2YfYp9iqINin2YTYrdmD2YjZhdmK2KkgKNmF2K/Y
rtmEINmF2KjYs9i3KQ0KDQrYp9mE2KPYrdivIDEg2YXYp9ix2LMgMjAyNg0KDQoqNyoNCg0K2YXZ
g9in2YHYrdipINin2YTZgdiz2KfYryDZiNiq2LnYstmK2LIg2KfZhNmG2LLYp9mH2Kkg2YjYp9mE
2KfZhNiq2LLYp9mFINin2YTZiNi42YrZgdmKDQoNCtin2YTYp9ir2YbZitmGIDIg2YXYp9ix2LMg
MjAyNg0KDQoqOCoNCg0K2KXYr9in2LHYqSDYp9mE2YXYrtin2LfYsSDYp9mE2YjYuNmK2YHZitip
INmB2Yog2KfZhNmC2LfYp9i5INin2YTYrdmD2YjZhdmKDQoNCtin2YTYq9mE2KfYq9in2KEgMyDZ
hdin2LHYsyAyMDI2DQoNCio5Kg0KDQrYqtmC2YrZitmFINin2YTYo9iv2KfYoSDYp9mE2YjYuNmK
2YHZiiDYqNin2LPYqtiu2K/Yp9mFINmF2KTYtNix2KfYqiDZhdio2LPYt9ipIChLUEkpDQoNCtin
2YTYo9ix2KjYudin2KEgNCDZhdin2LHYsyAyMDI2DQoNCioxMCoNCg0K2KXYr9in2LHYqSDYtti6
2YjYtyDYp9mE2LnZhdmEINmB2Yog2KfZhNmF2KTYs9iz2KfYqiDYp9mE2K3Zg9mI2YXZitipDQoN
Ctin2YTYrtmF2YrYsyA1INmF2KfYsdizIDIwMjYNCg0K2KfZhNij2LPYqNmI2Lkg2KfZhNir2KfZ
hNirICjZhdmGINin2YTYo9it2K8gOCDZhdin2LHYsyDYpdmE2Ykg2KfZhNiu2YXZitizIDEyINmF
2KfYsdizIDIwMjYpDQoNCioxMSoNCg0K2KfZhNiq2K3ZiNmEINin2YTYsdmC2YXZiiDZgdmKINin
2YTYudmF2YQg2KfZhNit2YPZiNmF2YogKNmF2YHYp9mH2YrZhSDZiNiq2LfYqNmK2YLYp9iqKQ0K
DQrYp9mE2KPYrdivIDgg2YXYp9ix2LMgMjAyNg0KDQoqMTIqDQoNCtin2YTYsNmD2KfYoSDYp9mE
2KfYtdi32YbYp9i52Yog2YHZiiDYqtit2LPZitmGINin2YTYrtiv2YXYp9iqINin2YTYrdmD2YjZ
hdmK2KkNCg0K2KfZhNin2KvZhtmK2YYgOSDZhdin2LHYsyAyMDI2DQoNCioxMyoNCg0K2KfZhNij
2YXZhiDYp9mE2LPZitio2LHYp9mG2Yog2YjYp9mE2YjYudmKINin2YTZiNi42YrZgdmKINmE2YXZ
htiz2YjYqNmKINin2YTYrNmH2KfYqiDYp9mE2K3Zg9mI2YXZitipDQoNCtin2YTYq9mE2KfYq9in
2KEgMTAg2YXYp9ix2LMgMjAyNg0KDQoqMTQqDQoNCtin2YTYp9iq2LXYp9mEINin2YTYrdmD2YjZ
hdmKINin2YTZgdi52ZHYp9mEDQoNCtin2YTYo9ix2KjYudin2KEgMTEg2YXYp9ix2LMgMjAyNg0K
DQoqMTUqDQoNCtin2YTZhdiv2K7ZhCDYp9mE2LnZhdmE2Yog2YTYsdmB2Lkg2YPZgdin2KHYqSDY
p9mE2YPZiNin2K/YsSDYp9mE2K3Zg9mI2YXZitipDQoNCtin2YTYrtmF2YrYsyAxMiDZhdin2LHY
syAyMDI2DQoNCtmK2LPYsdmR2YbYpyDYp9iz2KrZgtio2KfZhCDYqtix2LTZitit2KfYqtmD2YXY
jCDZhdi5INiq2YLYr9mK2YUg2YXYstin2YrYpyDYrtin2LXYqSDZhNmE2KrYsdi02YrYrdin2Kog
2KfZhNis2YXYp9i52YrYqS4NCg0K2YjYqtmB2LbZhNmI2Kcg2KjZgtio2YjZhCDZgdin2KbZgiDY
p9mE2KfYrdiq2LHYp9mF2IzYjNiMDQoNCtijLyDYs9in2LHYqSDYudio2K8g2KfZhNis2YjYp9iv
DQoNCiowMDIwMTA2OTk5NDM5OSAmIDAwMjAxKiowNjI5OTI1MTAqDQoNCtil2K/Yp9ix2Kkg2KfZ
hNiq2K/YsdmK2Kgg2YjYp9mE2KrYt9mI2YrYsSDYqNin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg
2YTZhNiq2YbZhdmK2Kkg2KfZhNil2K/Yp9ix2YrYqQ0KDQotLSAKWW91IHJlY2VpdmVkIHRoaXMg
bWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAi
a2FzYW4tZGV2IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdyb3VwIGFuZCBzdG9w
IHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byBrYXNhbi1kZXYrdW5z
dWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRpc2N1c3Npb24gdmlzaXQg
aHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9DQURqMVpLbUpSOWF2
OGlXY1k5VFdYMiUyQkpvb05DT1VPb2V3S3B5WEJySmtuTkRSMEJfdyU0MG1haWwuZ21haWwuY29t
Lgo=
--0000000000009003700649d479d3
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:115%;direction:rtl;unicode-bidi:embed;mar=
gin:0cm 0cm 8pt;font-size:11pt;font-family:Calibri,sans-serif;color:black">=
<span lang=3D"AR-SA" style=3D"font-size:24pt;line-height:115%;font-family:&=
quot;AlSharkTitle Black&quot;,sans-serif;color:rgb(0,102,0)">=D8=A8=D9=85=
=D9=86=D8=A7=D8=B3=D8=A8=D8=A9
=D8=AD=D9=84=D9=88=D9=84 =D8=B4=D9=87=D8=B1 =D8=B1=D9=85=D8=B6=D8=A7=D9=86 =
=D8=A7=D9=84=D9=85=D8=A8=D8=A7=D8=B1=D9=83</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:115%">=D9=8A=D8=B3=D8=B1=D9=91=D9=86=
=D8=A7 =D8=AA=D9=82=D8=AF=D9=8A=D9=85 =D8=AD=D8=B2=D9=85=D8=A9 =D8=A7=D9=84=
=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D8=B1=D9=85=D8=B6=D8=A7=D9=86=
=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D8=A7=D9=84=
=D9=87=D8=A7=D8=AF=D9=81=D8=A9 =D8=A5=D9=84=D9=89
=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D9=82=D8=AF=D8=B1=D8=A7=D8=AA =D9=85=D9=86=
=D8=B3=D9=88=D8=A8=D9=8A =D8=A7=D9=84=D8=AC=D9=87=D8=A7=D8=AA =D8=A7=D9=84=
=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9=D8=8C </span><span dir=3D"LTR" style=
=3D"font-size:14pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span dir=3D"RTL">=
</span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14p=
t;line-height:115%"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =D9=88=D8=AA=D8=B9=D8=B2=D9=8A=D8=B2
=D9=83=D9=81=D8=A7=D8=A1=D8=AA=D9=87=D9=85 =D8=A7=D9=84=D9=85=D9=87=D9=86=
=D9=8A=D8=A9=D8=8C =D9=88=D8=AA=D8=B1=D8=B3=D9=8A=D8=AE =D8=A7=D9=84=D9=82=
=D9=8A=D9=85 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=D8=A9=D8=8C =D8=A8=
=D9=85=D8=A7 =D9=8A=D9=88=D8=A7=D9=83=D8=A8 =D9=85=D8=AA=D8=B7=D9=84=D8=A8=
=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D8=AD=D9=83=D9=88=
=D9=85=D9=8A =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB</span><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:115%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span><=
span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:22pt;line-height:115%;font-family:&quot;AlSharkTitle =
Black&quot;,sans-serif;color:rgb(0,102,0)">=D8=B1=D9=85=D8=B6=D8=A7=D9=86=
=E2=80=A6
=D9=81=D8=B1=D8=B5=D8=A9 =D9=84=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1=D8=8C =
=D9=88=D8=A8=D8=AF=D8=A7=D9=8A=D8=A9 =D8=AC=D8=AF=D9=8A=D8=AF=D8=A9 =D9=84=
=D9=84=D8=AA=D9=85=D9=8A=D9=91=D8=B2 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=
=D9=8A</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:22pt;line-height:115%;font-family:&quot;AlSharkTit=
le Black&quot;,sans-serif;color:rgb(0,102,0)"><span dir=3D"LTR"></span><spa=
n dir=3D"LTR"></span>.</span><span lang=3D"AR-SA" style=3D"font-size:22pt;l=
ine-height:115%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color=
:rgb(0,102,0)"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:18pt;line-height:115%;font-family:&quot;AlSharkTitle =
Black&quot;,sans-serif;color:rgb(0,102,0)">=D8=A3=D9=87=D8=AF=D8=A7=D9=81
=D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;colo=
r:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdin=
gs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:=
auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-he=
ight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=B1=D9=81=D8=B9
=D9=83=D9=81=D8=A7=D8=A1=D8=A9 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=
=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=88=D8=A7=D9=84=D9=85=D8=A4=D8=B3=
=D8=B3=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdi=
ngs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning=
:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-h=
eight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=AA=D8=B9=D8=B2=D9=8A=D8=B2
=D8=A7=D9=84=D8=A7=D9=84=D8=AA=D8=B2=D8=A7=D9=85 =D8=A7=D9=84=D9=88=D8=B8=
=D9=8A=D9=81=D9=8A =D9=88=D8=A3=D8=AE=D9=84=D8=A7=D9=82=D9=8A=D8=A7=D8=AA =
=D8=A7=D9=84=D8=AE=D8=AF=D9=85=D8=A9 =D8=A7=D9=84=D8=B9=D8=A7=D9=85=D8=A9</=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdi=
ngs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning=
:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-h=
eight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=AA=D9=86=D9=85=D9=8A=D8=A9
=D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=B3=D9=84=D9=88=D9=83=D9=8A=
=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdi=
ngs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning=
:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-h=
eight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=AA=D8=AD=D8=B3=D9=8A=D9=86
=D8=AC=D9=88=D8=AF=D8=A9 =D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=85=
=D8=B9 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=81=D9=8A=D8=AF=D9=8A=D9=86 =D9=88=
=D8=A7=D9=84=D8=AC=D9=85=D9=87=D9=88=D8=B1</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdi=
ngs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning=
:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-h=
eight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=AF=D8=B9=D9=85
=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =
=D9=88=D8=A7=D9=84=D9=88=D8=B9=D9=8A =D8=A7=D9=84=D8=AA=D9=82=D9=86=D9=8A</=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;direction=
:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;color=
:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingding=
s">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:a=
uto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-hei=
ght:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=AA=D9=85=D9=83=D9=8A=D9=86
=D8=A7=D9=84=D9=83=D9=88=D8=A7=D8=AF=D8=B1 =D9=85=D9=86 =D8=A3=D8=AF=D9=88=
=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=
=D8=B3=D8=AA=D8=AF=D8=A7=D9=85</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:18pt;line-height:115%;font-family:&quot;AlSharkTitle =
Black&quot;,sans-serif;color:rgb(0,102,0)">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:18pt;line-height:115%;font-family:&quot;AlSharkTitle =
Black&quot;,sans-serif;color:rgb(0,102,0)">=D9=85=D8=AD=D8=A7=D9=88=D8=B1
=D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=
=D9=8A=D8=A8=D9=8A=D8=A9</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:115%;background:yellow">=D8=A7=D9=84=
=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 =D8=A7=D9=84=D8=A3=D9=88=D9=84 :
=D8=A7=D9=84=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D9=85=
=D9=87=D9=86=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=
=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:115%"=
></span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;colo=
r:black"><span style=3D"font-size:14pt;line-height:115%">1.<span style=3D"f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings=
:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&q=
uot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:11=
5%">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
=D8=A7=D9=84=D9=88=D9=82=D8=AA =D9=88=D8=A7=D9=84=D8=A7=D9=84=D8=AA=D8=B2=
=D8=A7=D9=85 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=81=D9=8A =D8=A7=
=D9=84=D8=AC=D9=87=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=
=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%">2.<span style=3D"=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;font-size-adjust:none;font-kerning:auto;font-feature-setting=
s:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&=
quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span di=
r=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:1=
15%">=D8=A7=D9=84=D8=B3=D9=84=D9=88=D9=83
=D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=88=D8=A3=D8=AE=D9=84=D8=A7=
=D9=82=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AE=D8=AF=D9=85=D8=A9 =D8=A7=D9=84=
=D8=B9=D8=A7=D9=85=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%">3.<span style=3D"=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;font-size-adjust:none;font-kerning:auto;font-feature-setting=
s:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&=
quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span di=
r=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:1=
15%">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
=D8=A7=D9=84=D8=AA=D9=82=D8=A7=D8=B1=D9=8A=D8=B1 =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D9=8A=D8=A9 =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9 =
=D8=A8=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%">4.<span style=3D"=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;font-size-adjust:none;font-kerning:auto;font-feature-setting=
s:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&=
quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span di=
r=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:1=
15%">=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA
=D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=85=D8=B9 =D8=A7=D9=84=D9=85=
=D8=B1=D8=A7=D8=AC=D8=B9=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D8=AC=D9=85=D9=87=
=D9=88=D8=B1</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;direction=
:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;color=
:black"><span style=3D"font-size:14pt;line-height:115%">5.<span style=3D"fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:11=
5%">=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A7=D8=AA
=D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A =
=D9=81=D9=8A =D8=A7=D9=84=D9=88=D8=B2=D8=A7=D8=B1=D8=A7=D8=AA =D9=88=D8=A7=
=D9=84=D9=87=D9=8A=D8=A6=D8=A7=D8=AA</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:115%;background:yellow">=D8=A7=D9=84=
=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 =D8=A7=D9=84=D8=AB=D8=A7=D9=86=D9=8A:
=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=88=D8=A7=D9=84=D8=A3=D8=AF=
=D8=A7=D8=A1 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;colo=
r:black"><span style=3D"font-size:14pt;line-height:115%">1.<span style=3D"f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings=
:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&q=
uot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:11=
5%">=D9=85=D8=A8=D8=A7=D8=AF=D8=A6
=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AC=
=D9=87=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9 (=D9=85=
=D8=AF=D8=AE=D9=84 =D9=85=D8=A8=D8=B3=D8=B7)</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%">2.<span style=3D"=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;font-size-adjust:none;font-kerning:auto;font-feature-setting=
s:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&=
quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span di=
r=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:1=
15%">=D9=85=D9=83=D8=A7=D9=81=D8=AD=D8=A9
=D8=A7=D9=84=D9=81=D8=B3=D8=A7=D8=AF =D9=88=D8=AA=D8=B9=D8=B2=D9=8A=D8=B2 =
=D8=A7=D9=84=D9=86=D8=B2=D8=A7=D9=87=D8=A9 =D9=88=D8=A7=D9=84=D8=A7=D9=84=
=D8=AA=D8=B2=D8=A7=D9=85 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A</span><=
/p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%">3.<span style=3D"=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;font-size-adjust:none;font-kerning:auto;font-feature-setting=
s:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&=
quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span di=
r=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:1=
15%">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
=D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=
=D9=81=D9=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=B9 =D8=A7=
=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%">4.<span style=3D"=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;font-size-adjust:none;font-kerning:auto;font-feature-setting=
s:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&=
quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span di=
r=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:1=
15%">=D8=AA=D9=82=D9=8A=D9=8A=D9=85
=D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=
=D9=8A =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D9=85=D8=A4=D8=B4=
=D8=B1=D8=A7=D8=AA =D9=85=D8=A8=D8=B3=D8=B7=D8=A9</span><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:115%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> (KPI)</s=
pan><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:115%"></span><=
/p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;direction=
:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;color=
:black"><span style=3D"font-size:14pt;line-height:115%">5.<span style=3D"fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:11=
5%">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
=D8=B6=D8=BA=D9=88=D8=B7 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D9=81=D9=8A =D8=A7=
=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=83=D9=88=
=D9=85=D9=8A=D8=A9</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:115%">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:115%">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:115%">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:115%;background:yellow">=D8=A7=D9=84=
=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 =D8=A7=D9=84=D8=AB=D8=A7=D9=84=D8=AB: =D8=A7=
=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1
=D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=
=D8=B3=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;colo=
r:black"><span style=3D"font-size:14pt;line-height:115%">1.<span style=3D"f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings=
:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&q=
uot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:11=
5%">=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84
=D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=B9=D9=85=
=D9=84 =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A (=D9=85=D9=81=D8=A7=D9=87=
=D9=8A=D9=85 =D9=88=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA)</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%">2.<span style=3D"=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;font-size-adjust:none;font-kerning:auto;font-feature-setting=
s:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&=
quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span di=
r=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:1=
15%">=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=88=D8=AF=D9=88=
=D8=B1=D9=87 =D9=81=D9=8A =D8=AA=D8=AD=D8=B3=D9=8A=D9=86 =D8=A7=D9=84=D8=AE=
=D8=AF=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9</=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%">3.<span style=3D"=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;font-size-adjust:none;font-kerning:auto;font-feature-setting=
s:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&=
quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span di=
r=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:1=
15%">=D8=A7=D9=84=D8=A3=D9=85=D9=86
=D8=A7=D9=84=D8=B3=D9=8A=D8=A8=D8=B1=D8=A7=D9=86=D9=8A =D9=88=D8=A7=D9=84=
=D9=88=D8=B9=D9=8A =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=84=D9=85=
=D9=86=D8=B3=D9=88=D8=A8=D9=8A =D8=A7=D9=84=D8=AC=D9=87=D8=A7=D8=AA =D8=A7=
=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%">4.<span style=3D"=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;font-size-adjust:none;font-kerning:auto;font-feature-setting=
s:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&=
quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span di=
r=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:1=
15%">=D8=A7=D9=84=D8=A7=D8=AA=D8=B5=D8=A7=D9=84
=D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A =D8=A7=D9=84=D9=81=D8=B9=D9=91=
=D8=A7=D9=84</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;direction=
:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;color=
:black"><span style=3D"font-size:14pt;line-height:115%">5.<span style=3D"fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:11=
5%">=D8=A7=D9=84=D9=85=D8=AF=D8=AE=D9=84
=D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A =D9=84=D8=B1=D9=81=D8=B9 =D9=83=D9=81=
=D8=A7=D8=A1=D8=A9 =D8=A7=D9=84=D9=83=D9=88=D8=A7=D8=AF=D8=B1 =D8=A7=D9=84=
=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:18pt;line-height:115%;font-family:&quot;AlSharkTitle =
Black&quot;,sans-serif;color:rgb(0,102,0)">=D8=A7=D9=84=D9=81=D8=A6=D8=A9
=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;colo=
r:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdin=
gs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:=
auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-he=
ight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D9=85=D9=86=D8=B3=D9=88=D8=A8=D9=88
=D8=A7=D9=84=D8=AC=D9=87=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=
=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdi=
ngs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning=
:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-h=
eight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A7=
=D8=AA
=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=A5=
=D8=B4=D8=B1=D8=A7=D9=81=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdi=
ngs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning=
:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-h=
eight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=B1=D8=A4=D8=B3=D8=A7=D8=A1
=D8=A7=D9=84=D8=A3=D9=82=D8=B3=D8=A7=D9=85 =D9=88=D8=A7=D9=84=D9=88=D8=AD=
=D8=AF=D8=A7=D8=AA</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdi=
ngs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning=
:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-h=
eight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=A7=D9=84=D9=83=D9=88=D8=A7=D8=AF=D8=B1
=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=81=
=D9=86=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;direction=
:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;color=
:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingding=
s">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:a=
uto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-hei=
ght:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=A7=D9=84=D9=85=D9=88=D8=B8=D9=81=D9=88=
=D9=86
=D8=A7=D9=84=D8=AC=D8=AF=D8=AF =D8=A8=D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=B9 =
=D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:115%">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:18pt;line-height:115%;font-family:&quot;AlSharkTitle =
Black&quot;,sans-serif;color:rgb(0,102,0)">=D9=85=D9=85=D9=8A=D8=B2=D8=A7=
=D8=AA
=D8=A7=D9=84=D8=B9=D8=B1=D8=B6 =D8=A7=D9=84=D8=B1=D9=85=D8=B6=D8=A7=D9=86=
=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;colo=
r:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdin=
gs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:=
auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-he=
ight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D9=85=D8=AD=D8=AA=D9=88=D9=89
=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A =D9=85=D8=AA=D8=AE=D8=B5=D8=B5 =D9=88=
=D9=85=D8=B1=D8=AA=D8=A8=D8=B7 =D8=A8=D8=A7=D9=84=D9=88=D8=A7=D9=82=D8=B9 =
=D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdi=
ngs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning=
:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-h=
eight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=B7=D8=B1=D8=AD =D9=85=D8=A8=D8=B3=D9=91=
=D8=B7
=D9=8A=D9=86=D8=A7=D8=B3=D8=A8 =D9=85=D8=AE=D8=AA=D9=84=D9=81 =D8=A7=D9=84=
=D9=85=D8=B3=D8=AA=D9=88=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D9=88=D8=B8=D9=8A=
=D9=81=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdi=
ngs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning=
:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-h=
eight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=A8=D9=8A=D8=A6=D8=A9
=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9 =D9=85=D8=AD=D9=81=D9=91=D8=B2=
=D8=A9 =D8=AE=D9=84=D8=A7=D9=84 =D8=B4=D9=87=D8=B1 =D8=B1=D9=85=D8=B6=D8=A7=
=D9=86</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;col=
or:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingdi=
ngs">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning=
:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-h=
eight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=AF=D8=B9=D9=85
=D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=
=D9=81=D9=8A =D9=88=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0cm 36pt 8pt 0cm;text-align:center;line-height:115%;direction=
:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif;color=
:black"><span style=3D"font-size:14pt;line-height:115%;font-family:Wingding=
s">=C3=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:a=
uto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-hei=
ght:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:115%">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9
=D8=AD=D8=B6=D9=88=D8=B1 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9 =D8=A8=D9=86=
=D9=87=D8=A7=D9=8A=D8=A9 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC</=
span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:115%">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:115%">=C2=A0</span></p>

<div align=3D"right" dir=3D"rtl">

<table class=3D"gmail-MsoTable15List4Accent6" dir=3D"rtl" border=3D"1" cell=
spacing=3D"0" cellpadding=3D"0" width=3D"689" style=3D"width:517pt;border-c=
ollapse:collapse;border:none">
 <tbody><tr style=3D"height:23.25pt">
  <td width=3D"689" nowrap colspan=3D"3" valign=3D"top" style=3D"width:517p=
t;border:1pt solid rgb(112,173,71);background:rgb(112,173,71);padding:0cm 5=
.4pt;height:23.25pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;col=
or:white">=D8=AD=D8=B2=D9=85=D8=A9
  =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=
=D9=8A=D8=A8=D9=8A=D8=A9 =D8=AE=D9=84=D8=A7=D9=84 =D8=B4=D9=87=D8=B1 =D8=B1=
=D9=85=D8=B6=D8=A7=D9=86 =D8=A7=D9=84=D9=85=D8=A8=D8=A7=D8=B1=D9=83=D9=80</=
span><span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;Calibri Li=
ght&quot;,sans-serif;color:white"></span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);background:rgb(226,239,217);padding:0cm 5.4pt;he=
ight:15pt"></td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);background:rgb(226,239,217);padding:0cm 5.4pt;height:15pt"></td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;background:rgb(226,239,217);padding:0cm 5.4pt;=
height:15pt"></td>
 </tr>
 <tr style=3D"height:18pt">
  <td width=3D"689" nowrap colspan=3D"3" valign=3D"top" style=3D"width:517p=
t;border-right:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(168,2=
08,141);border-left:1pt solid rgb(168,208,141);border-top:none;padding:0cm =
5.4pt;height:18pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif;bac=
kground:yellow">=D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 =D8=A7=D9=84=D8=
=A3=D9=88=D9=84=C2=A0 (=D9=85=D9=86 =D8=A7=D9=84=D8=A3=D8=AD=D8=AF 22
  =D9=81=D8=A8=D8=B1=D8=A7=D9=8A=D8=B1 =D8=A5=D9=84=D9=89 =D8=A7=D9=84=D8=
=AE=D9=85=D9=8A=D8=B3 26 =D9=81=D8=A8=D8=B1=D8=A7=D9=8A=D8=B1 2026)</span><=
span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;Calibri Light&qu=
ot;,sans-serif"></span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);background:rgb(226,239,217);padding:0cm 5.4pt;he=
ight:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><i><span lang=3D"AR-SA=
" style=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif">=
=D9=85</span></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);background:rgb(226,239,217);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D8=B3=D9=85 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC</span><=
/p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;background:rgb(226,239,217);padding:0cm 5.4pt;=
height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE</span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">1</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" st=
yle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></span=
></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=88=D9=82=D8=AA =D9=88=D8=A7=
=D9=84=D8=A7=D9=84=D8=AA=D8=B2=D8=A7=D9=85 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=
=D9=81=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=AC=D9=87=D8=A7=D8=AA =D8=A7=D9=84=
=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-=
size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif"></span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=A3=D8=AD=D8=AF 22 =D9=81=D8=A8=D8=B1=D8=A7=D9=8A=D8=B1 2026=
</span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);background:rgb(226,239,217);padding:0cm 5.4pt;he=
ight:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">2</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" st=
yle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></span=
></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);background:rgb(226,239,217);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=B3=D9=84=D9=88=D9=83 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=
=D9=8A =D9=88=D8=A3=D8=AE=D9=84=D8=A7=D9=82=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=
=D8=AE=D8=AF=D9=85=D8=A9
  =D8=A7=D9=84=D8=B9=D8=A7=D9=85=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif"></span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;background:rgb(226,239,217);padding:0cm 5.4pt;=
height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=A7=D8=AB=D9=86=D9=8A=D9=86 23 =D9=81=D8=A8=D8=B1=D8=A7=D9=
=8A=D8=B1 2026</span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">3</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" st=
yle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></span=
></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=A7=D9=84=D8=AA=D9=82=D8=A7=D8=B1=D9=8A=
=D8=B1 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D8=A7=D9=84=D8=AD=
=D9=83=D9=88=D9=85=D9=8A=D8=A9 =D8=A8=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81</=
span><span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;Calibri Li=
ght&quot;,sans-serif"></span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=AB=D9=84=D8=A7=D8=AB=D8=A7=D8=A1 24 =D9=81=D8=A8=D8=B1=D8=
=A7=D9=8A=D8=B1 2026</span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);background:rgb(226,239,217);padding:0cm 5.4pt;he=
ight:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">4</span></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);background:rgb(226,239,217);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=
=D9=84 =D9=85=D8=B9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D9=8A=D9=86
  =D9=88=D8=A7=D9=84=D8=AC=D9=85=D9=87=D9=88=D8=B1</span><span dir=3D"LTR" =
style=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif"><=
/span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;background:rgb(226,239,217);padding:0cm 5.4pt;=
height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=A3=D8=B1=D8=A8=D8=B9=D8=A7=D8=A1 25 =D9=81=D8=A8=D8=B1=D8=
=A7=D9=8A=D8=B1 2026</span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">5</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" st=
yle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></span=
></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D9=85=D9=84 =
=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=88=
=D8=B2=D8=A7=D8=B1=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D9=87=D9=8A=D8=A6=D8=A7=
=D8=AA</span><span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;Ca=
libri Light&quot;,sans-serif"></span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=AE=D9=85=D9=8A=D8=B3 26 =D9=81=D8=A8=D8=B1=D8=A7=D9=8A=D8=
=B1 2026</span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);background:rgb(226,239,217);padding:0cm 5.4pt;he=
ight:15pt"></td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);background:rgb(226,239,217);padding:0cm 5.4pt;height:15pt"></td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;background:rgb(226,239,217);padding:0cm 5.4pt;=
height:15pt"></td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);padding:0cm 5.4pt;height:15pt"></td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);padding:0cm 5.4pt;height:15pt"></td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;padding:0cm 5.4pt;height:15pt"></td>
 </tr>
 <tr style=3D"height:18pt">
  <td width=3D"689" nowrap colspan=3D"3" valign=3D"top" style=3D"width:517p=
t;border-right:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(168,2=
08,141);border-left:1pt solid rgb(168,208,141);border-top:none;background:r=
gb(226,239,217);padding:0cm 5.4pt;height:18pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif;bac=
kground:yellow">=D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 =D8=A7=D9=84=D8=
=AB=D8=A7=D9=86=D9=8A (=D9=85=D9=86 =D8=A7=D9=84=D8=A3=D8=AD=D8=AF 1 =D9=85=
=D8=A7=D8=B1=D8=B3 =D8=A5=D9=84=D9=89 =D8=A7=D9=84=D8=AE=D9=85=D9=8A=D8=B3 =
5 =D9=85=D8=A7=D8=B1=D8=B3 2026)</span><span dir=3D"LTR" style=3D"font-size=
:16pt;font-family:&quot;Calibri Light&quot;,sans-serif"></span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">6</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" st=
yle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></span=
></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D9=85=D8=A8=D8=A7=D8=AF=D8=A6 =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =
=D9=81=D9=8A =D8=A7=D9=84=D8=AC=D9=87=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=83=
=D9=88=D9=85=D9=8A=D8=A9 (=D9=85=D8=AF=D8=AE=D9=84 =D9=85=D8=A8=D8=B3=D8=B7=
)</span><span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;Calibri=
 Light&quot;,sans-serif"></span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=A3=D8=AD=D8=AF 1 =D9=85=D8=A7=D8=B1=D8=B3 2026</span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);background:rgb(226,239,217);padding:0cm 5.4pt;he=
ight:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">7</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" st=
yle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></span=
></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);background:rgb(226,239,217);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D9=85=D9=83=D8=A7=D9=81=D8=AD=D8=A9 =D8=A7=D9=84=D9=81=D8=B3=D8=A7=D8=AF =
=D9=88=D8=AA=D8=B9=D8=B2=D9=8A=D8=B2 =D8=A7=D9=84=D9=86=D8=B2=D8=A7=D9=87=
=D8=A9
  =D9=88=D8=A7=D9=84=D8=A7=D9=84=D8=AA=D8=B2=D8=A7=D9=85 =D8=A7=D9=84=D9=88=
=D8=B8=D9=8A=D9=81=D9=8A</span><span dir=3D"LTR" style=3D"font-size:16pt;fo=
nt-family:&quot;Calibri Light&quot;,sans-serif"></span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;background:rgb(226,239,217);padding:0cm 5.4pt;=
height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=A7=D8=AB=D9=86=D9=8A=D9=86 2 =D9=85=D8=A7=D8=B1=D8=B3 2026<=
/span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">8</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" st=
yle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></span=
></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1 =
=D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=
=D9=82=D8=B7=D8=A7=D8=B9 =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A</span><=
span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;Calibri Light&qu=
ot;,sans-serif"></span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=AB=D9=84=D8=A7=D8=AB=D8=A7=D8=A1 3 =D9=85=D8=A7=D8=B1=D8=B3=
 2026</span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);background:rgb(226,239,217);padding:0cm 5.4pt;he=
ight:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">9</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" st=
yle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></span=
></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);background:rgb(226,239,217);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=AA=D9=82=D9=8A=D9=8A=D9=85 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=
=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=
=D8=A7=D9=85
  =D9=85=D8=A4=D8=B4=D8=B1=D8=A7=D8=AA =D9=85=D8=A8=D8=B3=D8=B7=D8=A9 (</sp=
an><span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;Calibri Ligh=
t&quot;,sans-serif">KPI</span><span dir=3D"RTL"></span><span dir=3D"RTL"></=
span><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:&quot;Calibri=
 Light&quot;,sans-serif"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=
)</span><span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;Calibri=
 Light&quot;,sans-serif"></span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;background:rgb(226,239,217);padding:0cm 5.4pt;=
height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=A3=D8=B1=D8=A8=D8=B9=D8=A7=D8=A1 4 =D9=85=D8=A7=D8=B1=D8=B3=
 2026</span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">10</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" s=
tyle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></spa=
n></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=B6=D8=BA=D9=88=D8=B7 =D8=A7=D9=84=D8=B9=
=D9=85=D9=84 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =
=D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9</span><span dir=3D"LTR" st=
yle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif"></s=
pan></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=AE=D9=85=D9=8A=D8=B3 5 =D9=85=D8=A7=D8=B1=D8=B3 2026</span>=
</p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);background:rgb(226,239,217);padding:0cm 5.4pt;he=
ight:15pt"></td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);background:rgb(226,239,217);padding:0cm 5.4pt;height:15pt"></td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;background:rgb(226,239,217);padding:0cm 5.4pt;=
height:15pt"></td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);padding:0cm 5.4pt;height:15pt"></td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);padding:0cm 5.4pt;height:15pt"></td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;padding:0cm 5.4pt;height:15pt"></td>
 </tr>
 <tr style=3D"height:18pt">
  <td width=3D"689" nowrap colspan=3D"3" valign=3D"top" style=3D"width:517p=
t;border-right:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(168,2=
08,141);border-left:1pt solid rgb(168,208,141);border-top:none;background:r=
gb(226,239,217);padding:0cm 5.4pt;height:18pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif;bac=
kground:yellow">=D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 =D8=A7=D9=84=D8=
=AB=D8=A7=D9=84=D8=AB (=D9=85=D9=86 =D8=A7=D9=84=D8=A3=D8=AD=D8=AF 8 =D9=85=
=D8=A7=D8=B1=D8=B3 =D8=A5=D9=84=D9=89 =D8=A7=D9=84=D8=AE=D9=85=D9=8A=D8=B3 =
12 =D9=85=D8=A7=D8=B1=D8=B3 2026)</span><span dir=3D"LTR" style=3D"font-siz=
e:16pt;font-family:&quot;Calibri Light&quot;,sans-serif"></span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">11</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" s=
tyle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></spa=
n></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =
=D9=81=D9=8A =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D8=AD=D9=83=D9=88=
=D9=85=D9=8A (=D9=85=D9=81=D8=A7=D9=87=D9=8A=D9=85 =D9=88=D8=AA=D8=B7=D8=A8=
=D9=8A=D9=82=D8=A7=D8=AA)</span><span dir=3D"LTR" style=3D"font-size:16pt;f=
ont-family:&quot;Calibri Light&quot;,sans-serif"></span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=A3=D8=AD=D8=AF 8 =D9=85=D8=A7=D8=B1=D8=B3 2026</span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);background:rgb(226,239,217);padding:0cm 5.4pt;he=
ight:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">12</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" s=
tyle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></spa=
n></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);background:rgb(226,239,217);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=
=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=AA=D8=AD=D8=B3=D9=8A=D9=86 =D8=A7=D9=84=
=D8=AE=D8=AF=D9=85=D8=A7=D8=AA
  =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9</span><span dir=3D"LTR" =
style=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif"><=
/span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;background:rgb(226,239,217);padding:0cm 5.4pt;=
height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=A7=D8=AB=D9=86=D9=8A=D9=86 9 =D9=85=D8=A7=D8=B1=D8=B3 2026<=
/span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">13</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" s=
tyle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></spa=
n></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=A3=D9=85=D9=86 =D8=A7=D9=84=D8=B3=D9=8A=D8=A8=D8=B1=D8=A7=
=D9=86=D9=8A =D9=88=D8=A7=D9=84=D9=88=D8=B9=D9=8A =D8=A7=D9=84=D9=88=D8=B8=
=D9=8A=D9=81=D9=8A =D9=84=D9=85=D9=86=D8=B3=D9=88=D8=A8=D9=8A =D8=A7=D9=84=
=D8=AC=D9=87=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9</=
span><span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;Calibri Li=
ght&quot;,sans-serif"></span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=AB=D9=84=D8=A7=D8=AB=D8=A7=D8=A1 10 =D9=85=D8=A7=D8=B1=D8=
=B3 2026</span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);background:rgb(226,239,217);padding:0cm 5.4pt;he=
ight:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">14</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" s=
tyle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></spa=
n></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);background:rgb(226,239,217);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=A7=D8=AA=D8=B5=D8=A7=D9=84 =D8=A7=D9=84=D8=AD=D9=83=D9=88=
=D9=85=D9=8A =D8=A7=D9=84=D9=81=D8=B9=D9=91=D8=A7=D9=84</span><span dir=3D"=
LTR" style=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-ser=
if"></span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;background:rgb(226,239,217);padding:0cm 5.4pt;=
height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=A3=D8=B1=D8=A8=D8=B9=D8=A7=D8=A1 11 =D9=85=D8=A7=D8=B1=D8=
=B3 2026</span></p>
  </td>
 </tr>
 <tr style=3D"height:15pt">
  <td width=3D"47" nowrap valign=3D"top" style=3D"width:35.2pt;border-top:n=
one;border-left:none;border-bottom:1pt solid rgb(168,208,141);border-right:=
1pt solid rgb(168,208,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"LTR" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;font-size:11pt;font-family:Calibri,sans=
-serif;color:black"><i><span style=3D"font-size:12pt;font-family:&quot;Time=
s New Roman&quot;,serif">15</span></i><i><span lang=3D"AR-SA" dir=3D"RTL" s=
tyle=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,serif"></spa=
n></i></p>
  </td>
  <td width=3D"426" nowrap valign=3D"top" style=3D"width:319.5pt;border-top=
:none;border-right:none;border-left:none;border-bottom:1pt solid rgb(168,20=
8,141);padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D9=85=D8=AF=D8=AE=D9=84 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A =
=D9=84=D8=B1=D9=81=D8=B9 =D9=83=D9=81=D8=A7=D8=A1=D8=A9 =D8=A7=D9=84=D9=83=
=D9=88=D8=A7=D8=AF=D8=B1 =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9</=
span><span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;Calibri Li=
ght&quot;,sans-serif"></span></p>
  </td>
  <td width=3D"216" nowrap valign=3D"top" style=3D"width:162.3pt;border-top=
:none;border-left:1pt solid rgb(168,208,141);border-bottom:1pt solid rgb(16=
8,208,141);border-right:none;padding:0cm 5.4pt;height:15pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Calibri Light&quot;,sans-serif">=
=D8=A7=D9=84=D8=AE=D9=85=D9=8A=D8=B3 12 =D9=85=D8=A7=D8=B1=D8=B3 2026</span=
></p>
  </td>
 </tr>
</tbody></table>

</div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm 54p=
t 8pt 0cm;text-align:center;line-height:115%;direction:rtl;unicode-bidi:emb=
ed;font-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D=
"AR-SA" style=3D"font-size:16pt;line-height:115%">=D9=8A=D8=B3=D8=B1=D9=91=
=D9=86=D8=A7 =D8=A7=D8=B3=D8=AA=D9=82=D8=A8=D8=A7=D9=84 =D8=AA=D8=B1=D8=B4=
=D9=8A=D8=AD=D8=A7=D8=AA=D9=83=D9=85=D8=8C =D9=85=D8=B9 =D8=AA=D9=82=D8=AF=
=D9=8A=D9=85
=D9=85=D8=B2=D8=A7=D9=8A=D8=A7 =D8=AE=D8=A7=D8=B5=D8=A9 =D9=84=D9=84=D8=AA=
=D8=B1=D8=B4=D9=8A=D8=AD=D8=A7=D8=AA =D8=A7=D9=84=D8=AC=D9=85=D8=A7=D8=B9=
=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:16pt;line-height:115%"><span dir=3D"LTR"></s=
pan><span dir=3D"LTR"></span>.</span><span lang=3D"AR-SA" style=3D"font-siz=
e:16pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm 18p=
t 8pt 0cm;text-align:center;line-height:115%;direction:rtl;unicode-bidi:emb=
ed;font-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D=
"AR-SA" style=3D"font-size:16pt;line-height:115%">=D9=88=D8=AA=D9=81=D8=B6=
=D9=84=D9=88=D8=A7 =D8=A8=D9=82=D8=A8=D9=88=D9=84 =D9=81=D8=A7=D8=A6=D9=82 =
=D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=85=D8=8C=D8=8C=D8=8C</span></=
p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm 18p=
t 8pt 0cm;text-align:center;line-height:115%;direction:rtl;unicode-bidi:emb=
ed;font-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D=
"AR-SA" style=3D"font-size:24pt;line-height:115%;font-family:&quot;AlSharkT=
itle Black&quot;,sans-serif;color:rgb(0,102,0)">=D8=A3/ =D8=B3=D8=A7=D8=B1=
=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=A7=D8=AF</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><i><span lang=3D"A=
R-SA" style=3D"font-size:20pt;line-height:115%;font-family:&quot;Times New =
Roman&quot;,serif">00201069994399
&amp; 00201</span></i><i><span lang=3D"AR-SA" style=3D"font-size:18pt;line-=
height:115%;font-family:&quot;Times New Roman&quot;,serif">062992510</span>=
</i></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:16pt;line-height:115%">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9=
 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =D9=88=D8=A7=D9=84=D8=AA=D8=B7=
=D9=88=D9=8A=D8=B1 =D8=A8=D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=
=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=
=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;fo=
nt-size:11pt;font-family:Calibri,sans-serif;color:black"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:115%">=C2=A0</span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKmJR9av8iWcY9TWX2%2BJooNCOUOoewKpyXBrJknNDR0B_w%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CADj1ZKmJR9av8iWcY9TWX2%2BJooNCOUOoewKpyXBrJknNDR0B_w%40mail=
.gmail.com</a>.<br />

--0000000000009003700649d479d3--
