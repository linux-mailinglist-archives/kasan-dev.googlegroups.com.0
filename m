Return-Path: <kasan-dev+bncBD63B2HX4EPBBQNF4P7AKGQEDD33YVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 256DF2DAFD9
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 16:14:11 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id z125sf19143711ybb.15
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 07:14:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608045250; cv=pass;
        d=google.com; s=arc-20160816;
        b=f6L2cix3RNcMN+7DlQA9j4eQB7IxjvjOChekb325Q/4DJLzPPebBGjuCW6+rb20Pgl
         AgcG/LfI4INZb7ockxGT8bNi/CCwJaMgWTtJwnFecn8cVLcLKwF42g/14Eeep0B8TBJb
         rXlnSk+IpMCrc6BT4yOlCZgQ4OjgWOWLAbIqUpY1USpH//t2N3sD/Cs4Db5qO9XUeGgv
         4smb3IqDG/VMC6Nn16Y4IHBZXzy8FBwZbwuFHqAZ4xS/Ul6JDVhrM6qjbpTbchFt6Ps0
         67bSO1WXCa8RgOjM19q7C3WTprT92A2xxv9PKIprwP5a7DIzSVXFqbiUy0uWsExMcF7e
         JFkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=zqECxep+NG8fvpl0gqor078DGSn1c2EtD6rIcaS3u3M=;
        b=LlTQACLeMqzRYbC3al4oSAG0Gp77HdmLXbj4qbYpnt62bmFDMsTh3JdY3XinqmuCsb
         SE4RoY9S68oWfBrfBEz733rSRR6snNozJisE+3VxYbcM5DW9wRvKwQFqcUEM2mhrHBha
         lV7mwMC4lRybCSRj8Kjm5g0BhzdgnCmqDuNCJFz9FbrIkiTtNwlnU0pi+1IMSjj4FWD7
         MsBh35WMP/JV76akyXZBFDo6JCLS2Wr0p620CmBK9m2B5dgOr6r9EUEVaUkSsZAVKOML
         OJ7e4PKQs0SEtI9qT18BYOP0T91V9iqAo8cM4ik5v2jsNV5PKPhpx6cKDC9922tOR4Ay
         /8rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=ZL+7Moop;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:mime-version:content-disposition
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=zqECxep+NG8fvpl0gqor078DGSn1c2EtD6rIcaS3u3M=;
        b=J3+vYQ01T4zY4F0kHzQNp5Pacb+j3znunJk1fwaKTdG9u+YlGfuhhlBe+bVcdXSl9+
         EOX7Fq+WRPALuMqcZsuZ8dNy5fZmtGPHH+LTJNY/WGkci6jJ7BVc9G0zLLm6WLkAwpWe
         VfokzLAQcvBetKhn0DGP4q0lIyzvgPmFlyZpDJLA1GXARq09V+8cVZEST6OHXnT83Uz0
         /PrU0PevU89l9lzKBTDhqcqz2fEKawlpv72Fh8/TjwgPzI9RTz+yKAXitVrQgvj3G0Lz
         vzTUZ+w1F0K+t0Bl1flmEYSlAhAPQZbcO+2BoK1TSXtoSA95ivpel5lj6mX+5ohCERbv
         ceyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zqECxep+NG8fvpl0gqor078DGSn1c2EtD6rIcaS3u3M=;
        b=ukhKGSIF7x/McnBjU305fnnyOfhm4+StwqiqpCzcxF2P73AT6CYyOaE2pPUZ9sj/+w
         MBpUANAxAjwH/k0uGsrf614NZxK8Bsq7tYp0TNtSb//gmwsDKYuGpYtOFnr2aaEojj9v
         A3vyc852xZbtI4YUHrmF8OA1bDgf/AkkVXPe6/fDiBO7DcbQiRwQbO5YmaocDublY2Sy
         CLPPFEinzPeToJT5j0R8e5TBU7x9oJ1fIaS+hcAGOh2MyiDZXUhx6oUK4MaSj36fO/I1
         cSTv7WIMWtayEPC8mUn7Jsve0f7bA1U0O7ZV49zmQEqPBJm5cFWsS53KxSL8DMVTViBt
         Z4yQ==
X-Gm-Message-State: AOAM5333+5o5OEPYdwYEyw1LLu5glV1e/Z2Gk2Mp1s9rw1glq1BX1Ftu
	q3il0+lsjO5NS4IuD/IeU6k=
X-Google-Smtp-Source: ABdhPJz8GEUrh3DTvvUOsYfc8SrTOcvOAbfs+przY1dlHpT9CasbKmif1xCkqgpWFcehN/GShBPr/w==
X-Received: by 2002:a25:bbc2:: with SMTP id c2mr41808383ybk.170.1608045250023;
        Tue, 15 Dec 2020 07:14:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b581:: with SMTP id q1ls10101633ybj.6.gmail; Tue, 15 Dec
 2020 07:14:09 -0800 (PST)
X-Received: by 2002:a25:234c:: with SMTP id j73mr43418348ybj.116.1608045249462;
        Tue, 15 Dec 2020 07:14:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608045249; cv=none;
        d=google.com; s=arc-20160816;
        b=z0TQn/OFvvHj6dMPVFIuvZo0YOz+R7HYNqMe2zW7ZKnzTNvynL4dQIzQTJTceibkuY
         O2ACXOQJSsOBTafcH4EVhdpqLV3vsMpNecHlPyXhTxlBw/9bIDVy7X5I7Dsrc32o0csY
         GZ5dTI4//uVqn9GEpRwXTRpsmZEQZVHNmLYWdXl6UeX0vALQ7G9PdUY+vQJqizyroYR8
         tSc/7YONLkLM43L+byelNRpzPX67sgPgfBpT3TXieUEyZQfkSD4N1s1dQ1CKlivKhVQ1
         pswt/xRwIJhe0Is6owxUwpd4h/ONQe7JB17A3zDxbt9T30s7Wdut/eAp02pFxn0USBch
         umXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GMS8rLJI7JxAafL6llp7fOnk+GMHlldvql4mJwi5zuE=;
        b=L6uBzUNt1ALhXwGSytexDjznD/FcqNDYXt0RULK9E+RtyTlm4dlPodevoYM9EsxOsG
         6VO97zIeUvN6nEW8J3lG7UyYZGc78CwqCtYeOtSvHjmv04reSc1NZGkknlnT7bgMJmp+
         iM0rAV8UmhLbXORmn68YciqI65qTasVi7SinnBT92DfqpVWXoTacgSfhNIzCLPYXx4T5
         P5ac2TcmsV0pcqQDM8HJRv4LXlL1scTbmCUC/yOA32rek/DDICIj30hNXAzxIh0d2t6r
         f1WQP61apTHM+9RwRB61cEv6h5E/g8oAA+oEHLg/JkugJWQCGZXrwl45wLe0H+KwlGcG
         AE0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=ZL+7Moop;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id e10si292126ybp.4.2020.12.15.07.14.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Dec 2020 07:14:09 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id b5so7562985pjk.2
        for <kasan-dev@googlegroups.com>; Tue, 15 Dec 2020 07:14:09 -0800 (PST)
X-Received: by 2002:a17:902:d351:b029:db:d63d:d0e with SMTP id l17-20020a170902d351b02900dbd63d0d0emr26197387plk.75.1608045248731;
        Tue, 15 Dec 2020 07:14:08 -0800 (PST)
Received: from cork (c-73-93-175-39.hsd1.ca.comcast.net. [73.93.175.39])
        by smtp.gmail.com with ESMTPSA id i184sm5869396pfe.126.2020.12.15.07.14.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Dec 2020 07:14:08 -0800 (PST)
Date: Tue, 15 Dec 2020 07:14:01 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: stack_trace_save skip
Message-ID: <20201215151401.GA3865940@cork>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=ZL+7Moop;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::1029
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

We're getting kfence reports, which is good.  But the reports include a
fair amount of noise, for example:

	BUG: KFENCE: out-of-bounds in kfence_report_error+0x6f/0x4a0

	Out-of-bounds access at 0xffff88be95497000 (16B right of kfence-#46922):
	 kfence_report_error+0x6f/0x4a0
	 kfence_handle_page_fault+0xe2/0x200
	 no_context+0x90/0x2f0
	 __bad_area_nosemaphore+0x123/0x210
	 bad_area_nosemaphore+0x14/0x20
	 __do_page_fault+0x1d6/0x4b0
	 do_page_fault+0x22/0x30
	 page_fault+0x25/0x30
	 parse_wwn+0x20/0xf0
	 ...

I would like to remove the first 8 lines.  But if I increase the skip
parameter by 8, the code becomes fragile.  An unrelated change that
inlines __do_page_fault() or __bad_area_nosemaphore() would result in us
losing the most important part of the backtrace.

That seems to be a hard problem in general.  An alternative
stack_trace_save() implementation could have an "ignore-after"
parameter.  If the stacktrace happens to come across an address inside
page_fault(), it would remove the previous output.  Code would be less
fragile, but renaming page_fault() to something else would still be a
problem.

Have any of you spent time on this issue?  Good ideas are welcome.

J=C3=B6rn

--
Ninety percent of everything is crap.
-- Sturgeon's Law

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201215151401.GA3865940%40cork.
