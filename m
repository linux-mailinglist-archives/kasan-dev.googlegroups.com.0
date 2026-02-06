Return-Path: <kasan-dev+bncBC7M7IOXQAGRBG5ZTHGAMGQE2CPNC6Y@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 2CPrBJ5chmlfMQQAu9opvQ
	(envelope-from <kasan-dev+bncBC7M7IOXQAGRBG5ZTHGAMGQE2CPNC6Y@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Feb 2026 22:26:54 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id A7271103693
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Feb 2026 22:26:53 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-50620483ff6sf82299521cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Feb 2026 13:26:53 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1770413212; cv=pass;
        d=google.com; s=arc-20240605;
        b=S/lWYGBD8WXF2Rb9F699buSI8vCE6NKLoVfWEGWkwO3CX5Ro68Qtmr+RSLnt6OeX0Y
         atHtFoOLcstnZVKJ6tOqBGWcGt2hNT4RcqCKy1bSBerHgDc0pTiZxzGwi3xZJHHiTXPI
         +9wUD8zEhTCTTIfxbn/J3XnjBw3h8OImroWRmw7it3mCBg8orumbMFkcWiuh1p/WdNhb
         zfQWEzlFBjtGstbVDQUQ4W96CBaNKRw7rGASsTBaNPTUEYAnfusVEETkOKePjPK1XqRE
         sNshrHVvw33m7/8UPb/b7Iaay9pmoPDFbuAw8tb6qMrBobCAnoUcTFOwxWb8cYwj8IQW
         BgFw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4H3zN4G3wTg1ByDPbka35iTAoa3wrnO7cb7uYfkiWfM=;
        fh=RoG12elJoN+tY4S4VlKxtL1xt4ilqeSynVjnwI+iugM=;
        b=HWadVwvj27GK1U+iuaDFFKzlSxynjYkrgH8iq4f3ehQflz/wk7hY+mCDvzZNL3l6oD
         r7QR9ql2wKIvWuNLvnrJz2E+3h26wQU3GPvIVy9QjIpFVZX+Vbh3HVZpiyW+GcsWZ5yH
         rGAV4l5SXEajHgVHCNvHBYa6W33KZywufr7QKZO5FDfkDh8AFNdYWwN1gJtLE9MlBdPZ
         +5hSdrGs2UxZXsgvUmKebvueGL3JabiWyFNXfusUWuLrBz2aQWLD806TL+Afrywht8Is
         8PcqRI7ih3d77Wkh0U+ws82wnQ8HmbCrm4iUm09okUOUoBvTyG90VdMegdBTM407ID8H
         YGyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=B1bkkeom;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770413212; x=1771018012; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4H3zN4G3wTg1ByDPbka35iTAoa3wrnO7cb7uYfkiWfM=;
        b=Gp4uzPxJiWLl5VqGoOGGrvg6nKvoCTlGrGi40wotyH7MOOV9C5H4O3lQsX/hagv218
         w2KiEEVY51U2otOGNQ0rIICIRDeyhugIebfDRD894BvW4gLPa09/xNBTy4w+Gt4GnceI
         sV6pU7J0DjGzL3F43G9exY8sH3uQTzu4qI8cEe3S6pTFXWBNlzB6iofLFbvkNe02uyFy
         unJaepohgJ/bGGoKNy/gxjzhEgNTV/hGshRHhTWAmzjTxqDA4X8V7Ox8nJyEqUcsel0C
         RPuMq0sYC9+CmF4ZqiMNql1bTVs/2EUIdEwKDs2Wn7VipVpdqxefNiZfRGZcZ9YhGnia
         MGWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770413212; x=1771018012;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4H3zN4G3wTg1ByDPbka35iTAoa3wrnO7cb7uYfkiWfM=;
        b=T+StfcXviJU6a9GnVMLl3qghMgZ42D611M3oPivrrMTvuIJxROyus1voyh6fAPzZU9
         +eLk94ZSHWci4phL73K8Pozqx42a1jDs+m4CcYlbJQfejq0+CZgSkrVL56CGBivlEjla
         0gDJSWhOJxmpCv1/FctyutPtHN8tCzmk1v4TwHKL5y39UI9nvJzgWdTJSr3TonhQJvUM
         k1vPUJdkrf1VKVG75HcnJ3ZtXuJcnmI1NKK0CM9BVPFIdL5su0lg5aMwF5qSQAWTK/ys
         /ioZB186AHIIe4APz56gMIHOCm9f6ngcP3ZdnyG5CYDn3/2VW1Vb/h0ZfMHzSeNOOY2I
         v8kQ==
X-Forwarded-Encrypted: i=3; AJvYcCXghsqB+RrFN6jLCtPCy3/yVPQNmWhcpTl96Lb/kPPvwa1BqdtuAtOebED+TN2Mf9EcHcM/xQ==@lfdr.de
X-Gm-Message-State: AOJu0YzChkdU3wPYNrm1cqJsXX407V8nDRBkHFgzkBZ6DTrntLIOEm+B
	/LDLG8doekzqVDzRlKXG2Bg1RhLvZIg2opE2UBcJYx7Kx/YDUfKa5IQO
X-Received: by 2002:a05:622a:1496:b0:502:a97c:d8da with SMTP id d75a77b69052e-506399a1568mr56235871cf.70.1770413211879;
        Fri, 06 Feb 2026 13:26:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FL5nmXcLNzvYKU/JFxuwSqyqP0kSCreXTNpKnJuIALyw=="
Received: by 2002:ac8:5ac2:0:b0:503:3943:9068 with SMTP id d75a77b69052e-5062ab06788ls43948951cf.2.-pod-prod-03-us;
 Fri, 06 Feb 2026 13:26:51 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCV53nJmiyLyX0cWk2yynDoAI0/+BPmQQZDmoXZjjhDEfHGGjCTV+wXTW4VLyuv49xRkL3Ub1+qoSSw=@googlegroups.com
X-Received: by 2002:ac8:5787:0:b0:502:a27c:cc1 with SMTP id d75a77b69052e-5063986a439mr55446431cf.4.1770413211041;
        Fri, 06 Feb 2026 13:26:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770413211; cv=pass;
        d=google.com; s=arc-20240605;
        b=R6okf/ZN9ve7BaPp8KoAo22all2VMDJf2yXnk4Am1GKkl5jvWMu0pJCmEFBPwx1G9N
         424R2MMCuJ3DkeM/j1YZlKOR5BryXUHvs5ddzWwQgWdljV4I6+aQY/bSgFU0rnTPeUiQ
         Ok8WQmu0OwP2wPrhSvv6TCWe7iVEu8T2wS8VV+oLYcB/l1pbzEC8qhHZ75oBG+aiV8TT
         6DZGbl+F8YVpMqSCynod1zAiIJGk8OIDE3TrKgl4ImnSy+ZNiGy0tw1vgMkxHG3Cj7wl
         0SKiHmJd+5bQf1mEKdlq/1eAf7NgLbgxFltvn57tGT+wNXWpouYNIySIGEbYNM0Le7eh
         vXdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=e2vRt91HE57LlxbsBX+S8iZ8+RLwY1B3JoqVasfqz+Y=;
        fh=ZuGs94B/HWr4UlkMfaJVQsIA42EbBfclhZfT3OKoR+Y=;
        b=Tz5uJoVGefMVtAIqXQuS8u7/7BAJn3EQpJDOmL4TYEuyTutGI/yyCIu8wfpk/bhLaZ
         IAV0M5Ql7Wv7adJt39ebLi8mL3AEnhurUwjzWp1EFGFN+8KPevOThiTmuLVtTIsPNnIS
         PRVfkDLa6/meBOU0THnzCqiE+jrxbDhUtzOcYIexMI7ALBUEYNIREVUcbIpsFiJOTaNj
         SF1IKIcUzePeF+XEmaZOdCw5x/eVSLZjpOrnMFLHRhEv+2U6PLB0t+wyYr/Ze30vgjnY
         cSdmf56xfU7LueB2fO8MWxp/9amRxvki9AYYFQDeRoFilpER5labNA3SwL31XzeiYb64
         Cg4Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=B1bkkeom;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x836.google.com (mail-qt1-x836.google.com. [2607:f8b0:4864:20::836])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-506391403c6si1436331cf.1.2026.02.06.13.26.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Feb 2026 13:26:51 -0800 (PST)
Received-SPF: pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::836 as permitted sender) client-ip=2607:f8b0:4864:20::836;
Received: by mail-qt1-x836.google.com with SMTP id d75a77b69052e-5014b5d8551so20791cf.0
        for <kasan-dev@googlegroups.com>; Fri, 06 Feb 2026 13:26:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770413211; cv=none;
        d=google.com; s=arc-20240605;
        b=eLk01PyM12moy9hFt8vOysoOW8NNnFYlDJ2WXTkF1M6pWvWtI4I12Egi1PQ0KltgTd
         2K9qHektg5Lt+5X2YWwaWe3joTs831K/xjyMkgr1qfpc2OjHV1dLJGgWCfcpngC+03t1
         2dleSE39tEqCCGZPNgwMnBzvhlIldfsDLIH2X9WYCUKlZDv7sgBaE+N3oEnRSNDh0NxP
         xwoYYRinih8D5zYS9mZg5CfUiFxgHZ4VfuH1v2J0U/wAocRs0kvQ8xOCsXUlwl1tX7AX
         h9PrcbikURSawxcVlIJtDNoaUCxsKREwKRMjrfv8jkwIhlZ3J3UZrcDZuu//iNTH4S6T
         Ubcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=e2vRt91HE57LlxbsBX+S8iZ8+RLwY1B3JoqVasfqz+Y=;
        fh=ZuGs94B/HWr4UlkMfaJVQsIA42EbBfclhZfT3OKoR+Y=;
        b=Wm8ZI6Agmn8clidqxkWgx1CoZpd3BMecAk47eqMhNWkRBkwthUNM2967jAl60l6KTl
         qv3+htNRCLX9KrJeaGH/xmqxjwQ82xX8FAUhJKbsMEdoIRrefIyTEHvXihikC2psKLEc
         OigpEAt26Yt1N6wH2UNb/ttq0O/JrpF5OY85lOgdbMYrsiaMpUDa+w6+Dm0jHhg3ldz6
         Wfia01NP2Rk/zs5HBNawf6uF0eDFL+XPjoL0/+6CvjX1/EnR4VeaLInStrXhZYbTusqr
         Dg1Nj9Cch9Kh3XOEw6fbOVYDoFriMYskQ0mbqAD3G7UjeaA+iIOy1jTtDETW8AwpNrZw
         AbPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXe9Dt9RzDDwifzQ+ycO3Vn3ne7cloFCncZlKKw5tVoabVKfk+4c8rv1l0zTDTVsVZTD3vPSLvFaN8=@googlegroups.com
X-Gm-Gg: AZuq6aJwn9V7PoGe4+2QjQbxqVJChMRfqBMvvISMMxlFBiCIcICHT9VWIIL4/YgpakU
	Ozf33FUesVutF3pKKVz9AE6wk0VA+8cB/CmzswyyQtuIov0d73XMCS3p5Dlb9Cw89hLX5NbyKtT
	GflTY5ERbUlQ0YGSUDUtAzqm2/CCwRoYU/SqMJYzcJSuVS6rlfsZ1V4WNFOmBTMBjIgtzH4ay1K
	DnIcJFE1LOXSJo3DwxnyRsrFhBQy8ABul/SkFM2WoWzEyzIh5GIs7pKYxWTS7C8EJgpvCYfPo0l
	nUV47QMRTSkgXif6UQl44oU6B8gM5w==
X-Received: by 2002:a05:622a:1b89:b0:4ff:a98b:7fd3 with SMTP id
 d75a77b69052e-50649b6ad07mr2258111cf.2.1770413210149; Fri, 06 Feb 2026
 13:26:50 -0800 (PST)
MIME-Version: 1.0
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <202601071226.8DF7C63@keescook> <btracv3snpi6l4b5upqvag6qz3j4d2k7l7qgzj665ft5m7bn22@m3y73eir2tnt>
 <CANP3RGfLXptZp6widUEyvVzicAB=dwcSx3k7MLtQozhO0NuxZw@mail.gmail.com>
 <CANP3RGeaEQipgRvk2FedpN54Rrq=fKdLs3PN4_+DThpeqQmTXA@mail.gmail.com>
 <CANP3RGcNFgLSgKYPjmro2s1Es04Pnhf+4wHpnSwRX4M8bLDW9g@mail.gmail.com>
 <aWFKEDwwihxGIbQA@wieczorr-mobl1.localdomain> <CANP3RGeWLMQEMnC03pUr8=1+e27vma1ggiWGWcpX+PcZ=SsxUg@mail.gmail.com>
 <CANP3RGeHnhufYyc0P2OiKJbXdZjPW41TP=JS6nYk9xGRU8UuKQ@mail.gmail.com> <aYZJ2Ohug6b9Vth0@wieczorr-mobl1.localdomain>
In-Reply-To: <aYZJ2Ohug6b9Vth0@wieczorr-mobl1.localdomain>
From: =?UTF-8?Q?=27Maciej_=C5=BBenczykowski=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Date: Fri, 6 Feb 2026 13:26:37 -0800
X-Gm-Features: AZwV_QguewADB-2xma46o3PunJjIPEerBNilNQhrGaSGk5f8ofWHwvj9j70yzs8
Message-ID: <CANP3RGerB8-soNb1pBx7TqmOivR7Vp4Q-iqjE5QH0fzHrxEseQ@mail.gmail.com>
Subject: Re: KASAN vs realloc
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Kees Cook <kees@kernel.org>, 
	joonki.min@samsung-slsi.corp-partner.google.com, 
	Andrew Morton <akpm@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	Danilo Krummrich <dakr@kernel.org>, jiayuan.chen@linux.dev, 
	syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	Kernel hackers <linux-kernel@vger.kernel.org>, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: maze@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=B1bkkeom;       arc=pass
 (i=1);       spf=pass (google.com: domain of maze@google.com designates
 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
Reply-To: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7M7IOXQAGRBG5ZTHGAMGQE2CPNC6Y];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_COUNT_THREE(0.00)[4];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[19];
	FREEMAIL_CC(0.00)[gmail.com,kernel.org,samsung-slsi.corp-partner.google.com,google.com,arm.com,linux-foundation.org,linux.dev,syzkaller.appspotmail.com,intel.com,googlegroups.com,vger.kernel.org,kvack.org];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[maze@google.com];
	TAGGED_RCPT(0.00)[kasan-dev,997752115a851cb0cf36];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,mail-qt1-x83a.google.com:helo,mail-qt1-x83a.google.com:rdns,googlegroups.com:email,googlegroups.com:dkim,pm.me:email]
X-Rspamd-Queue-Id: A7271103693
X-Rspamd-Action: no action

On Fri, Feb 6, 2026 at 12:14=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From what I see kasan_poison_last_granule() is called through:
>
> __kasan_vrealloc()
> --> __kasan_unpoison_vmalloc()
> ----> kasan_unpoison()
> ------> kasan_poison_last_granule()
>
> and the arguments are "addr + old_size" and "new_size - old_size" so it l=
ooks
> okay I think.

Cool, thanks for checking.

> On 2026-02-06 at 11:07:12 -0800, Maciej =C5=BBenczykowski wrote:
> >While looking at:
> >  https://android-review.git.corp.google.com/c/kernel/common/+/3939998
> >  UPSTREAM: mm/kasan: fix KASAN poisoning in vrealloc()
> >
> >I noticed a lack of symmetry - I'm not sure if it's a problem or not...
> >but I'd have expected kasan_poison_last_granule() to be called
> >regardless of whether the size shrunk or increased.
> >
> >It is of course possible this is handled automatically by
> >__kasan_unpoison_vmalloc() - I haven't traced that deep,
> >in general these functions seem to have a terrible api surface full of
> >razors... with hidden assumptions about what is and is not granule
> >aligned.
>
> --
> Kind regards
> Maciej Wiecz=C3=B3r-Retman
>

--
Maciej =C5=BBenczykowski, Kernel Networking Developer @ Google

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANP3RGerB8-soNb1pBx7TqmOivR7Vp4Q-iqjE5QH0fzHrxEseQ%40mail.gmail.com.
