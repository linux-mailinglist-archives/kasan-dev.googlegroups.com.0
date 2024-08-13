Return-Path: <kasan-dev+bncBDO456PHTELBB5UK5W2QMGQEHD7AZAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3227C9503DA
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 13:37:28 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-26123f60850sf6689263fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 04:37:28 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723549047; x=1724153847; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=NlhfNhyQtM9jRNDDVutCWUT5XCPpAiCTGZDfn1J0ipQ=;
        b=SWEUZdjTtu8wjj03ectTdfC1W6Ltd1Ve5QDgcmitRzk5pnCBthrN7IL7nsOWtjkD8b
         D+z3myHX8404o+PnjannTFdHu+58D+khgox9Z2xpfJ+1KM1+tkWvq5vZfK3fBOtD40cN
         XFZPMHEXj0wTkq3pXPD+aAso+sXzniYExTs9xV7QsjRLB9o4ryl6Xby1pbwYT3kAiwWJ
         b3phchJ/hzpRE0NOvtCq1V4n0geB3j+01z/OX79TJyb0hYJh6al0qGF3n5/I0LhixAEr
         XRQFMX21v+HWcJA4YrlcmEw0NruO2BclO2CmzOHiJb5MpKEQXSDLS2CBBA6BuSQC1PXN
         hUPQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723549047; x=1724153847; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NlhfNhyQtM9jRNDDVutCWUT5XCPpAiCTGZDfn1J0ipQ=;
        b=JZurEKuKenQo+MJ7xJ9ic8fZvtMjUt144kUN3azxyFNgdMYpvu1W/Bfd9dDjiskueP
         uW4IvHE4/bSXp1/bBnabId/yyjQK3r1PW/AVKAUjX6BnAjYERerFGTQL7/gqt7r7Cu5V
         E5ZOyLl6eQLhVEcg7MTTI/T0GQEay2/Dvi+wqmI/v8U3K61EKT5224Jmq9YElAPyP++g
         Oi4bB5eLpZPbfk6WE8KbIv86hdfg2+5mbcKcHz0WI84WBDk/qHKKYCkfYbBofWeq+1+K
         g6MmS4zfu9/u45YxQEcm9Izd1K5eBPuAx94TQRnZLOCouDybVr8OmUKowp5BuAC9StJL
         Pj6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723549047; x=1724153847;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=NlhfNhyQtM9jRNDDVutCWUT5XCPpAiCTGZDfn1J0ipQ=;
        b=RKomb8ZmQxe9UQqm7GAitKD3KwbB3le9+ne206GvJ9UbUsnotwrl6AVG8fdNDqKbjK
         +pu3Og2/CGw87Yqe3d6+sU08xs8BDL3fQvqG+tksGh1XuKvZFg88hL4hKl7QzxOHQudj
         GCgWbH2vHCtQpfCOkWJZwvVbKyMuyR2NH2MsbuvWCR6kWXQ/Xl6pJe0Py8HMTxTvYnf2
         KjQ+ZcA5ZDaFJveJvFZmH0VNoa/DOHskpW0KNERuMHHDNSsnxlZE+o8GKx8y8zR9c0pK
         9QvDUSD0hQRn8fHVKYi+lVt7NLWZZ65s00mZdC0ZvnYX9fRB15aHF1t8SXT7tWOuUy27
         eDTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCXTh3OdAbJ7jfoHm89gx85jF+o8giJCLOPVGg7ztE9ExsmYZ8Jb0xhpNw/LAA8BBq7UKDBIP2wwBgATYDtfrH7iJCSs+0DmRA==
X-Gm-Message-State: AOJu0YyWgT1atDcs13SgmZMnkj4HCMNC7hJN5gEa7xrf6kR9jN6RvzqJ
	tKjm75ShxMKMUYfFxC2F6mlbURhTfm2ASZE+roLLPa8QWZU3J1iI
X-Google-Smtp-Source: AGHT+IFebcLLjK18vkAGq4Z/6jRZh03NGmeEEdWDwOBDcBK6vc4OoKiejMbZRHxTrTbPuNXVz9jvnA==
X-Received: by 2002:a05:6870:610e:b0:260:df77:2484 with SMTP id 586e51a60fabf-26fcb696059mr3480995fac.13.1723549046685;
        Tue, 13 Aug 2024 04:37:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2b04:b0:25c:b2bf:2226 with SMTP id
 586e51a60fabf-26925379cd2ls2449709fac.1.-pod-prod-07-us; Tue, 13 Aug 2024
 04:37:25 -0700 (PDT)
X-Received: by 2002:a05:6808:1203:b0:3d9:2e65:1a03 with SMTP id 5614622812f47-3dd1ee84292mr162694b6e.5.1723549045560;
        Tue, 13 Aug 2024 04:37:25 -0700 (PDT)
Date: Tue, 13 Aug 2024 04:37:24 -0700 (PDT)
From: hana soodi <hanasoodi668@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <dd5647b3-6a18-4e5b-afaa-930fdf16de24n@googlegroups.com>
In-Reply-To: <7fa1582b-ffe1-4ad0-8945-d322396d070an@googlegroups.com>
References: <7fa1582b-ffe1-4ad0-8945-d322396d070an@googlegroups.com>
Subject: =?UTF-8?B?UmU6INmF2YrYstmIINiq2KfZgyDYqNix2YjYrNiz2Kog2LPYp9mK2KrZiNiq?=
 =?UTF-8?B?2YjZgyDYqNix2YrYt9in2YbZiiDYtdmK?=
 =?UTF-8?B?2K/ZhNmK2Kkg2KfZhNmG2YfYr9mKINiu2LU=?=
 =?UTF-8?B?2YUg2KfYs9i52KfYsSDZhdmC2KjZiNmE2KkgY3l0b3RlYyDYp9mE2LM=?=
 =?UTF-8?B?2LnZiNiv2YrYqSAwMCBoZ3ZkaHE5NzE1NTMwMzE4NDY=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_37224_933645634.1723549044911"
X-Original-Sender: hanasoodi668@gmail.com
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

------=_Part_37224_933645634.1723549044911
Content-Type: multipart/alternative; 
	boundary="----=_Part_37225_959300882.1723549044911"

------=_Part_37225_959300882.1723549044911
Content-Type: text/plain; charset="UTF-8"

https://linktr.ee/cytotic_d_nur

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dd5647b3-6a18-4e5b-afaa-930fdf16de24n%40googlegroups.com.

------=_Part_37225_959300882.1723549044911
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

https://linktr.ee/cytotic_d_nur<br /><br />

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/dd5647b3-6a18-4e5b-afaa-930fdf16de24n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/dd5647b3-6a18-4e5b-afaa-930fdf16de24n%40googlegroups.com</a>.<b=
r />

------=_Part_37225_959300882.1723549044911--

------=_Part_37224_933645634.1723549044911--
