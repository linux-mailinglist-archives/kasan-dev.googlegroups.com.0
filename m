Return-Path: <kasan-dev+bncBDAOJ6534YNBBY4JV64AMGQE52MZ3YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CC5C99B979
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 15:02:28 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-43123d8a33dsf10753485e9.3
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 06:02:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728824548; cv=pass;
        d=google.com; s=arc-20240605;
        b=Tu58IZq4bUfwQpGpMnFfPVokEd+2rCEd7MAQe15fSjca4rmmZRXOTCITYVPlxQxZYP
         22FTXPpVrwYQ54KHKOVrXOOi9mVUIwKH8DC6R13tgtXONuKl2h1BJrjzLJfuzvG422di
         CJclywjkD3QnuPUiRR/M2QtCSWAYs7F7+HggTQ6c1ggXmTdQ7QWauoExLMdIx2qfUTCe
         yW4B/DWr6cZe2/euww1ZQI0reliv97s3CAeFRkMRWrOkxw5oWkj7joE/Ehf/qfhUuwkh
         5Y8MeSjHz642IIKMRnFB+sw0uJNcW2lNsLFsaMTkFCin03+ONYLbz0phJxSlWXmaG6H2
         4fXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=FvtrANNbqWl/r05S5X2rqL5Kbif9guspAv5Ke4I+UD0=;
        fh=tsOJQkpzZUgkZjUY62p01TgBpsUq2TwuoJsAWh+RmiM=;
        b=UqCy2DPwZXb8JpOmYsLWZeV74HYDwE7bscqxNCCkDBUzB6DRWGo/sjSURJdBx9Gk8j
         39WwsKipY3zpjMm7ulPrzB5xYZQuLA9Q/Uu3FpwwVRjmIE6lKKUxOs2rV4Ifh7GSMCz2
         mFVI0kZpVKQSRILi39vSEA+IR2cHGCDhi7NUPv5HY4FKyu1Ycc69iL1JfHcT8CFA+c7Q
         UtXLHoet4sdtIJ07FUoxdcMdm3vjyzr5x+f6izwfYrskdCPz/Q2pd2bg6NGcNc/o0QmG
         mUbfkpUxgfDXykp2WHsH/DHQY6WheUEMk2J23tMycLY2al25w0S/bLTr9K/7o+hoaCwb
         E4rw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TJv577dQ;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728824548; x=1729429348; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FvtrANNbqWl/r05S5X2rqL5Kbif9guspAv5Ke4I+UD0=;
        b=NYB4SDQr+PP7E9futfYkrw3I1nyTmjNv1H0eOflptB99efRcbVXdx1+HJm3m6KIpOi
         IwEfYeQMe9Y5vJe+ehi7knrOX2Ih2cvb2jCbbhBegms2rjXu+3iWqRLRaoArPTWT1XwQ
         g38S6KEjHWngLLREznx5a9UuDTW5ws6vDshjqZUijF/a3j5Ll4iOVAgdGjfGg9PJ3Uke
         L5TLlEDf56UMBfypK5s+vRG1/l9lbdOzg8ZhRZT/BnenLSjuNFijFQa/ZliQm27IBJUD
         lsMalPTGKFBiE7/XBRFu+nsh4xCZWN7XgxDmRnCjSHIHaEnA9p8nnGQEThf2HJimH9hU
         rLZg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728824548; x=1729429348; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=FvtrANNbqWl/r05S5X2rqL5Kbif9guspAv5Ke4I+UD0=;
        b=CATZM35Hwau5yyE8JylXSDqurZULk26IRxK1RIKsQCmeCPkrNhvowSR3uXPiXdnk2S
         hBgeVFthzlJPHJzr1ima6gnrs8XyE36VANEFXiHvj/5Kpvtq6n3Hf/MerihX65dJo2fo
         hdGEERrUh02dL+K6tOCeHV4jwFMeLC0P0h3RC5gvIfE1a6l+amzkPjZQ6JPKbs9iVTeB
         IH9PqAu4RIBtuMYb/ML8btTrbjfsw4tST8UOk/RnbjcI58nKUeqYYsQ63jz7kIYo2eWm
         JA9u9F+PReSuEojqY84vW9B5i3DbPjGcow7CV5fgOqGl5Nc4HqJbQBQIIDjM/0IiJ0XY
         oc1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728824548; x=1729429348;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FvtrANNbqWl/r05S5X2rqL5Kbif9guspAv5Ke4I+UD0=;
        b=L2opUNPZzpw71RAv/shcSVHUFU0xdicIyP6E8f2GKSIBDPvGFY0lI0WRi70essgcfW
         q0XhbxOYm2t8ykEmJKVx4SpA0BXqFx9CTb4/PpfZ2JjPsP4FO2hzL065b/cZTRv0g4oM
         IYtvepBH4IGQgA0Jh3MfJbtV5IKesUnVIxX/TYVnKlS+KPEGQGc0Znj4Zx0NcVpM1NYt
         /n9lLcEY8rGFyL3EAmvUPbh+ezZaaBhYbBDPb5koa9Z8giHuz2KAQfd7uMHWcRfCs5JL
         wnwjRdaoejielk2W2ElW3iMZCRM24yMB16r1cY3SrxCl2Hvnim4QTHOEYFGnAXa5LMGy
         s6+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVxiO3pvWKkMID8r50z4NUJ1gsbSvFCk+JrQWj1XqFRI6ss71Dfm582SP9F4+cUjEIoFQfPGA==@lfdr.de
X-Gm-Message-State: AOJu0YygFosQMkBAZx6PSj/vxa7veIcpVDNHXUD4M/EBdFdPVBIih3kR
	mhgMHuj023HMlGAZio7tgFBPU+3zNdZDvmNJsT2kyGwVD7pKPdvo
X-Google-Smtp-Source: AGHT+IFMV8S4w2rkcuxdN40c5k5Bhb66BWspj+hv20cdzvOEa9ZqcM7mxDnNmF9ey6hpIP6X6Nj41g==
X-Received: by 2002:a05:600c:1c06:b0:42e:d463:3ea8 with SMTP id 5b1f17b1804b1-4311df5c482mr71370865e9.34.1728824547592;
        Sun, 13 Oct 2024 06:02:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c9f:b0:431:155e:348e with SMTP id
 5b1f17b1804b1-43115f179e2ls6794955e9.0.-pod-prod-02-eu; Sun, 13 Oct 2024
 06:02:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUY1qTLRMnancfVAPnegsDOaDR15F/3D/PxdeI2knQhL7gRx6w/VYcoK7ho3PjBj9/E1mw5pdBbFz8=@googlegroups.com
X-Received: by 2002:adf:e50e:0:b0:37d:4ef1:1820 with SMTP id ffacd0b85a97d-37d5529e91amr5256289f8f.40.1728824545769;
        Sun, 13 Oct 2024 06:02:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728824545; cv=none;
        d=google.com; s=arc-20240605;
        b=FV75xxmUYlwxBpL+QQpDwZVPHrBEnSG0cQp5oBCvAoi6HjCqmzy9Hmgd2VESccx9GT
         PMst9YovP3WquZjRMtYZzNSxA+d8flqxHspCx/sjyDyXpktghcCGi8z2i5MLz70PxUYc
         ACs9zlLSERi5fbUOOl70xwvZhg4wAfNTET9SRt7N5HWxHOI9DOfJ+OWdcdaZvHzFni/A
         TkKdzc3w7nDtQ/VM+97f0NXO6W5oVmEN4Z01j9aKfpgSpnY15CK3PUehaWm3CSey+0gM
         MqvYtUHgX/TNRQTXkqKLWJK2mgLpHGlZP+yfYHRx1NDaePwaV1PP5NwnTcWiccliDEQ9
         CAnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pqumvoIyJhkt9W5HwjJwb/i/n9g4P9IeX/TAEyTfGvM=;
        fh=Y09EIPQbTSFmU5zFgOU7m2Bpzj25EB8z0JgM6YyneyE=;
        b=e8OqzXWNrzyZCS/HKMTR+k2kU3MZYdptgrXsRbPJrrVmUTondACCE3Li6HotlQMLmB
         I2gLeqnDYGUd+Lf3Se1yElA+4cshXZVAD2vy5b2AnoBsR9/h8FWjZRcCCW72bxueKx9C
         IzA7VCokEBoSEyq+tZVuSZVyrx+GnCh0fQbfm34arzGAOaNq3i/uW6ofx5hDx3/++RMj
         hu0uPltvzBb88erOrO6SgKZfck4OXUUSf6jkwUA5ppnCnu+lf40fbeDAVnKszcKTZTse
         5Jq3I4PgZsAnFLLr/jlb5/pgcpertpbGFhQDZfXNan7PG2irxBAw7xlLd4X/mITQ2z9M
         6bKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TJv577dQ;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-431177238dasi3461165e9.0.2024.10.13.06.02.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 06:02:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id a640c23a62f3a-a9a0472306cso59216766b.3
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 06:02:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVhwW261IvWZOctnNSOnX786Bsd7LRUWcRN4fAB9UI13cXZWXlRs1hAZZz2lt4LQZbKQGCChToVrEs=@googlegroups.com
X-Received: by 2002:a17:907:9723:b0:a99:ef41:33db with SMTP id a640c23a62f3a-a99ef4137ebmr460504966b.19.1728824544896;
        Sun, 13 Oct 2024 06:02:24 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a9a0d9de967sm19209666b.139.2024.10.13.06.02.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Oct 2024 06:02:24 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: akpm@linux-foundation.org,
	dvyukov@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	snovitoll@gmail.com,
	vincenzo.frascino@arm.com,
	elver@google.com,
	corbet@lwn.net,
	alexs@kernel.org,
	siyanteng@loongson.cn,
	2023002089@link.tyut.edu.cn,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org
Subject: [PATCH v2 3/3] kasan: delete CONFIG_KASAN_MODULE_TEST
Date: Sun, 13 Oct 2024 18:02:11 +0500
Message-Id: <20241013130211.3067196-4-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241013130211.3067196-1-snovitoll@gmail.com>
References: <CA+fCnZdeuNxTmGaYniiRMhS-TtNhiwj_MwW53K73a5Wiui+8RQ@mail.gmail.com>
 <20241013130211.3067196-1-snovitoll@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TJv577dQ;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::62b
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

U2luY2Ugd2UndmUgbWlncmF0ZWQgYWxsIHRlc3RzIHRvIHRoZSBLVW5pdCBmcmFtZXdvcmssDQp3
ZSBjYW4gZGVsZXRlIENPTkZJR19LQVNBTl9NT0RVTEVfVEVTVCBhbmQgbWVudGlvbmluZyBvZiBp
dCBpbiB0aGUNCmRvY3VtZW50YXRpb24gYXMgd2VsbC4NCg0KSSd2ZSB1c2VkIHRoZSBvbmxpbmUg
dHJhbnNsYXRvciB0byBtb2RpZnkgdGhlIG5vbi1FbmdsaXNoIGRvY3VtZW50YXRpb24uDQoNClNp
Z25lZC1vZmYtYnk6IFNhYnlyemhhbiBUYXNib2xhdG92IDxzbm92aXRvbGxAZ21haWwuY29tPg0K
LS0tDQogRG9jdW1lbnRhdGlvbi9kZXYtdG9vbHMva2FzYW4ucnN0ICAgICAgICAgICAgICAgICAg
ICB8IDkgKystLS0tLS0tDQogRG9jdW1lbnRhdGlvbi90cmFuc2xhdGlvbnMvemhfQ04vZGV2LXRv
b2xzL2thc2FuLnJzdCB8IDYgKy0tLS0tDQogRG9jdW1lbnRhdGlvbi90cmFuc2xhdGlvbnMvemhf
VFcvZGV2LXRvb2xzL2thc2FuLnJzdCB8IDYgKy0tLS0tDQogbGliL0tjb25maWcua2FzYW4gICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB8IDcgLS0tLS0tLQ0KIG1tL2thc2FuL2th
c2FuLmggICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfCAyICstDQogbW0va2Fz
YW4vcmVwb3J0LmMgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB8IDIgKy0NCiA2
IGZpbGVzIGNoYW5nZWQsIDYgaW5zZXJ0aW9ucygrKSwgMjYgZGVsZXRpb25zKC0pDQoNCmRpZmYg
LS1naXQgYS9Eb2N1bWVudGF0aW9uL2Rldi10b29scy9rYXNhbi5yc3QgYi9Eb2N1bWVudGF0aW9u
L2Rldi10b29scy9rYXNhbi5yc3QNCmluZGV4IGQ3ZGU0NGY1MzM5Li41MmZkZDZiNWVmNiAxMDA2
NDQNCi0tLSBhL0RvY3VtZW50YXRpb24vZGV2LXRvb2xzL2thc2FuLnJzdA0KKysrIGIvRG9jdW1l
bnRhdGlvbi9kZXYtdG9vbHMva2FzYW4ucnN0DQpAQCAtNTExLDE3ICs1MTEsMTIgQEAgVGVzdHMN
CiB+fn5+fg0KIA0KIFRoZXJlIGFyZSBLQVNBTiB0ZXN0cyB0aGF0IGFsbG93IHZlcmlmeWluZyB0
aGF0IEtBU0FOIHdvcmtzIGFuZCBjYW4gZGV0ZWN0DQotY2VydGFpbiB0eXBlcyBvZiBtZW1vcnkg
Y29ycnVwdGlvbnMuIFRoZSB0ZXN0cyBjb25zaXN0IG9mIHR3byBwYXJ0czoNCitjZXJ0YWluIHR5
cGVzIG9mIG1lbW9yeSBjb3JydXB0aW9ucy4NCiANCi0xLiBUZXN0cyB0aGF0IGFyZSBpbnRlZ3Jh
dGVkIHdpdGggdGhlIEtVbml0IFRlc3QgRnJhbWV3b3JrLiBFbmFibGVkIHdpdGgNCitUZXN0cyB0
aGF0IGFyZSBpbnRlZ3JhdGVkIHdpdGggdGhlIEtVbml0IFRlc3QgRnJhbWV3b3JrLiBFbmFibGVk
IHdpdGgNCiBgYENPTkZJR19LQVNBTl9LVU5JVF9URVNUYGAuIFRoZXNlIHRlc3RzIGNhbiBiZSBy
dW4gYW5kIHBhcnRpYWxseSB2ZXJpZmllZA0KIGF1dG9tYXRpY2FsbHkgaW4gYSBmZXcgZGlmZmVy
ZW50IHdheXM7IHNlZSB0aGUgaW5zdHJ1Y3Rpb25zIGJlbG93Lg0KIA0KLTIuIFRlc3RzIHRoYXQg
YXJlIGN1cnJlbnRseSBpbmNvbXBhdGlibGUgd2l0aCBLVW5pdC4gRW5hYmxlZCB3aXRoDQotYGBD
T05GSUdfS0FTQU5fTU9EVUxFX1RFU1RgYCBhbmQgY2FuIG9ubHkgYmUgcnVuIGFzIGEgbW9kdWxl
LiBUaGVzZSB0ZXN0cyBjYW4NCi1vbmx5IGJlIHZlcmlmaWVkIG1hbnVhbGx5IGJ5IGxvYWRpbmcg
dGhlIGtlcm5lbCBtb2R1bGUgYW5kIGluc3BlY3RpbmcgdGhlDQota2VybmVsIGxvZyBmb3IgS0FT
QU4gcmVwb3J0cy4NCi0NCiBFYWNoIEtVbml0LWNvbXBhdGlibGUgS0FTQU4gdGVzdCBwcmludHMg
b25lIG9mIG11bHRpcGxlIEtBU0FOIHJlcG9ydHMgaWYgYW4NCiBlcnJvciBpcyBkZXRlY3RlZC4g
VGhlbiB0aGUgdGVzdCBwcmludHMgaXRzIG51bWJlciBhbmQgc3RhdHVzLg0KIA0KZGlmZiAtLWdp
dCBhL0RvY3VtZW50YXRpb24vdHJhbnNsYXRpb25zL3poX0NOL2Rldi10b29scy9rYXNhbi5yc3Qg
Yi9Eb2N1bWVudGF0aW9uL3RyYW5zbGF0aW9ucy96aF9DTi9kZXYtdG9vbHMva2FzYW4ucnN0DQpp
bmRleCA0NDkxYWQyODMwZS4uZjk2OGQyNjJiZTEgMTAwNjQ0DQotLS0gYS9Eb2N1bWVudGF0aW9u
L3RyYW5zbGF0aW9ucy96aF9DTi9kZXYtdG9vbHMva2FzYW4ucnN0DQorKysgYi9Eb2N1bWVudGF0
aW9uL3RyYW5zbGF0aW9ucy96aF9DTi9kZXYtdG9vbHMva2FzYW4ucnN0DQpAQCAtNDIyLDE0ICs0
MjIsMTAgQEAgS0FTQU7ov57mjqXliLB2bWFw5Z+656GA5p625p6E5Lul5oeS5riF55CG5pyq5L2/
55So55qE5b2x5a2Q5YaF5a2Y44CCDQogfn5+fg0KIA0KIOacieS4gOS6m0tBU0FO5rWL6K+V5Y+v
5Lul6aqM6K+BS0FTQU7mmK/lkKbmraPluLjlt6XkvZzlubblj6/ku6Xmo4DmtYvmn5Dkupvnsbvl
novnmoTlhoXlrZjmjZ/lnY/jgIINCi3mtYvor5XnlLHkuKTpg6jliIbnu4TmiJA6DQogDQotMS4g
5LiOS1VuaXTmtYvor5XmoYbmnrbpm4bmiJDnmoTmtYvor5XjgILkvb/nlKggYGBDT05GSUdfS0FT
QU5fS1VOSVRfVEVTVGBgIOWQr+eUqOOAgg0KK+S4jktVbml05rWL6K+V5qGG5p626ZuG5oiQ55qE
5rWL6K+V44CC5L2/55SoIGBgQ09ORklHX0tBU0FOX0tVTklUX1RFU1RgYCDlkK/nlKjjgIINCiDo
v5nkupvmtYvor5Xlj6/ku6XpgJrov4flh6Dnp43kuI3lkIznmoTmlrnlvI/oh6rliqjov5DooYzl
kozpg6jliIbpqozor4HvvJvor7flj4LpmIXkuIvpnaLnmoTor7TmmI7jgIINCiANCi0yLiDkuI5L
VW5pdOS4jeWFvOWuueeahOa1i+ivleOAguS9v+eUqCBgYENPTkZJR19LQVNBTl9NT0RVTEVfVEVT
VGBgIOWQr+eUqOW5tuS4lOWPquiDveS9nOS4uuaooeWdlw0KLei/kOihjOOAgui/meS6m+a1i+iv
leWPquiDvemAmui/h+WKoOi9veWGheaguOaooeWdl+W5tuajgOafpeWGheaguOaXpeW/l+S7peiO
t+WPlktBU0FO5oql5ZGK5p2l5omL5Yqo6aqM6K+B44CCDQotDQog5aaC5p6c5qOA5rWL5Yiw6ZSZ
6K+v77yM5q+P5LiqS1VuaXTlhbzlrrnnmoRLQVNBTua1i+ivlemDveS8muaJk+WNsOWkmuS4qktB
U0FO5oql5ZGK5LmL5LiA77yM54S25ZCO5rWL6K+V5omT5Y2wDQog5YW257yW5Y+35ZKM54q25oCB
44CCDQogDQpkaWZmIC0tZ2l0IGEvRG9jdW1lbnRhdGlvbi90cmFuc2xhdGlvbnMvemhfVFcvZGV2
LXRvb2xzL2thc2FuLnJzdCBiL0RvY3VtZW50YXRpb24vdHJhbnNsYXRpb25zL3poX1RXL2Rldi10
b29scy9rYXNhbi5yc3QNCmluZGV4IGVkMzQyZTY3ZDhlLi4xOTQ1Nzg2MDQ4NiAxMDA2NDQNCi0t
LSBhL0RvY3VtZW50YXRpb24vdHJhbnNsYXRpb25zL3poX1RXL2Rldi10b29scy9rYXNhbi5yc3QN
CisrKyBiL0RvY3VtZW50YXRpb24vdHJhbnNsYXRpb25zL3poX1RXL2Rldi10b29scy9rYXNhbi5y
c3QNCkBAIC00MDQsMTQgKzQwNCwxMCBAQCBLQVNBTumAo+aOpeWIsHZtYXDln7rnpI7mnrbmp4vk
u6Xmh7bmuIXnkIbmnKrkvb/nlKjnmoTlvbHlrZDlhaflrZjjgIINCiB+fn5+DQogDQog5pyJ5LiA
5LqbS0FTQU7muKzoqablj6/ku6XpqZforYlLQVNBTuaYr+WQpuato+W4uOW3peS9nOS4puWPr+S7
peaqoua4rOafkOS6m+mhnuWei+eahOWFp+WtmOaQjeWjnuOAgg0KLea4rOippueUseWFqemDqOWI
hue1hOaIkDoNCiANCi0xLiDoiIdLVW5pdOa4rOippuahhuaetumbhuaIkOeahOa4rOippuOAguS9
v+eUqCBgYENPTkZJR19LQVNBTl9LVU5JVF9URVNUYGAg5ZWT55So44CCDQor6IiHS1VuaXTmuKzo
qabmoYbmnrbpm4bmiJDnmoTmuKzoqabjgILkvb/nlKggYGBDT05GSUdfS0FTQU5fS1VOSVRfVEVT
VGBgIOWVk+eUqOOAgg0KIOmAmeS6m+a4rOippuWPr+S7pemAmumBjuW5vueoruS4jeWQjOeahOaW
ueW8j+iHquWLlemBi+ihjOWSjOmDqOWIhumpl+itie+8m+iri+WPg+mWseS4i+mdoueahOiqquaY
juOAgg0KIA0KLTIuIOiIh0tVbml05LiN5YW85a6555qE5ris6Kmm44CC5L2/55SoIGBgQ09ORklH
X0tBU0FOX01PRFVMRV9URVNUYGAg5ZWT55So5Lim5LiU5Y+q6IO95L2c54iy5qih5aGKDQot6YGL
6KGM44CC6YCZ5Lqb5ris6Kmm5Y+q6IO96YCa6YGO5Yqg6LyJ5YWn5qC45qih5aGK5Lim5qqi5p+l
5YWn5qC45pel6KqM5Lul542y5Y+WS0FTQU7loLHlkYrkvobmiYvli5XpqZforYnjgIINCi0NCiDl
poLmnpzmqqLmuKzliLDpjK/oqqTvvIzmr4/lgItLVW5pdOWFvOWuueeahEtBU0FO5ris6Kmm6YO9
5pyD5omT5Y2w5aSa5YCLS0FTQU7loLHlkYrkuYvkuIDvvIznhLblvozmuKzoqabmiZPljbANCiDl
hbbnt6jomZ/lkozni4DmhYvjgIINCiANCmRpZmYgLS1naXQgYS9saWIvS2NvbmZpZy5rYXNhbiBi
L2xpYi9LY29uZmlnLmthc2FuDQppbmRleCA5ODAxNmUxMzdiNy4uZjgyODg5YTgzMGYgMTAwNjQ0
DQotLS0gYS9saWIvS2NvbmZpZy5rYXNhbg0KKysrIGIvbGliL0tjb25maWcua2FzYW4NCkBAIC0x
OTUsMTMgKzE5NSw2IEBAIGNvbmZpZyBLQVNBTl9LVU5JVF9URVNUDQogCSAgRm9yIG1vcmUgaW5m
b3JtYXRpb24gb24gS1VuaXQgYW5kIHVuaXQgdGVzdHMgaW4gZ2VuZXJhbCwgcGxlYXNlIHJlZmVy
DQogCSAgdG8gdGhlIEtVbml0IGRvY3VtZW50YXRpb24gaW4gRG9jdW1lbnRhdGlvbi9kZXYtdG9v
bHMva3VuaXQvLg0KIA0KLWNvbmZpZyBLQVNBTl9NT0RVTEVfVEVTVA0KLQl0cmlzdGF0ZSAiS1Vu
aXQtaW5jb21wYXRpYmxlIHRlc3RzIG9mIEtBU0FOIGJ1ZyBkZXRlY3Rpb24gY2FwYWJpbGl0aWVz
Ig0KLQlkZXBlbmRzIG9uIG0gJiYgS0FTQU4gJiYgIUtBU0FOX0hXX1RBR1MNCi0JaGVscA0KLQkg
IEEgcGFydCBvZiB0aGUgS0FTQU4gdGVzdCBzdWl0ZSB0aGF0IGlzIG5vdCBpbnRlZ3JhdGVkIHdp
dGggS1VuaXQuDQotCSAgSW5jb21wYXRpYmxlIHdpdGggSGFyZHdhcmUgVGFnLUJhc2VkIEtBU0FO
Lg0KLQ0KIGNvbmZpZyBLQVNBTl9FWFRSQV9JTkZPDQogCWJvb2wgIlJlY29yZCBhbmQgcmVwb3J0
IG1vcmUgaW5mb3JtYXRpb24iDQogCWRlcGVuZHMgb24gS0FTQU4NCmRpZmYgLS1naXQgYS9tbS9r
YXNhbi9rYXNhbi5oIGIvbW0va2FzYW4va2FzYW4uaA0KaW5kZXggZjQzOGE2Y2RjOTYuLmI3ZTRi
ODE0MjFiIDEwMDY0NA0KLS0tIGEvbW0va2FzYW4va2FzYW4uaA0KKysrIGIvbW0va2FzYW4va2Fz
YW4uaA0KQEAgLTU2OCw3ICs1NjgsNyBAQCBzdGF0aWMgaW5saW5lIHZvaWQga2FzYW5fa3VuaXRf
dGVzdF9zdWl0ZV9lbmQodm9pZCkgeyB9DQogDQogI2VuZGlmIC8qIENPTkZJR19LQVNBTl9LVU5J
VF9URVNUICovDQogDQotI2lmIElTX0VOQUJMRUQoQ09ORklHX0tBU0FOX0tVTklUX1RFU1QpIHx8
IElTX0VOQUJMRUQoQ09ORklHX0tBU0FOX01PRFVMRV9URVNUKQ0KKyNpZiBJU19FTkFCTEVEKENP
TkZJR19LQVNBTl9LVU5JVF9URVNUKQ0KIA0KIGJvb2wga2FzYW5fc2F2ZV9lbmFibGVfbXVsdGlf
c2hvdCh2b2lkKTsNCiB2b2lkIGthc2FuX3Jlc3RvcmVfbXVsdGlfc2hvdChib29sIGVuYWJsZWQp
Ow0KZGlmZiAtLWdpdCBhL21tL2thc2FuL3JlcG9ydC5jIGIvbW0va2FzYW4vcmVwb3J0LmMNCmlu
ZGV4IGI0OGM3NjhhY2M4Li4zZTQ4NjY4YzNlNCAxMDA2NDQNCi0tLSBhL21tL2thc2FuL3JlcG9y
dC5jDQorKysgYi9tbS9rYXNhbi9yZXBvcnQuYw0KQEAgLTEzMiw3ICsxMzIsNyBAQCBzdGF0aWMg
Ym9vbCByZXBvcnRfZW5hYmxlZCh2b2lkKQ0KIAlyZXR1cm4gIXRlc3RfYW5kX3NldF9iaXQoS0FT
QU5fQklUX1JFUE9SVEVELCAma2FzYW5fZmxhZ3MpOw0KIH0NCiANCi0jaWYgSVNfRU5BQkxFRChD
T05GSUdfS0FTQU5fS1VOSVRfVEVTVCkgfHwgSVNfRU5BQkxFRChDT05GSUdfS0FTQU5fTU9EVUxF
X1RFU1QpDQorI2lmIElTX0VOQUJMRUQoQ09ORklHX0tBU0FOX0tVTklUX1RFU1QpDQogDQogYm9v
bCBrYXNhbl9zYXZlX2VuYWJsZV9tdWx0aV9zaG90KHZvaWQpDQogew0KLS0gDQoyLjM0LjENCg0K
LS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQg
dG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2NyaWJlIGZy
b20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4g
ZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRvIHZpZXcg
dGhpcyBkaXNjdXNzaW9uIG9uIHRoZSB3ZWIgdmlzaXQgaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNv
bS9kL21zZ2lkL2thc2FuLWRldi8yMDI0MTAxMzEzMDIxMS4zMDY3MTk2LTQtc25vdml0b2xsJTQw
Z21haWwuY29tLgo=
