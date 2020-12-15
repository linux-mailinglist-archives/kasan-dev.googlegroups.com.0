Return-Path: <kasan-dev+bncBAABBTF34L7AKGQEWUEOLSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id C54642DABE9
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 12:28:14 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id bj5sf6340551pjb.9
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 03:28:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608031693; cv=pass;
        d=google.com; s=arc-20160816;
        b=BWFJuhlU9Ra1dJif8lH7Dy3pD+OVEGhktp+z9Enzeg5KSloVU3OplOToYIcDtJ/27N
         Y8q108GHwhtG8O1a8I93yT+8uOzOM+otivEGCWs8YwbclTUBlZdf5C9BAXKTxoWKvw/U
         mlTyvN/p0FdN4xsl+o6XLvIA4fjZ3ELKAkD1nnKHhZiEvJqpLvOF6yFVzTc0V1x7VsQm
         EIsmLRypNvVAWUbLAQAuTXW43DR4vnBG6wqsL2i7aW0zsQEZRaBI7t2EmcetvwJufJ8x
         1vy2zSlQolAbpIYpHEVCWHLXdlsssh5nyqgR8yxidHesHU2YQaOH/Dc2zFgOiiHarrC7
         8fLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=N9w0ao85Eknm/KN+XsjJ7wUADghVqfHB84LDtTvPu94=;
        b=LeVPXWbG5+GwHBrGBvFBosmT2E+VWxYo5Z2uCWkH77XrWfXicqEQEVsI4OeDJPfsIB
         oF8uYf4c0nxC9xIi1c5sJJZ3Ti5aHOXsCBkCkp38tk+99blnRHMJGBnZmpObecVDNeMf
         FDvlG7H4VLJ37CpSmKa6NhiPAm3xAbwkZTyl3mKg9v+ucKZJjfymbol7Apna4fjC596j
         ieUZfgJ7wcL3o3qtD5L53IuFnWrs/3RLfoqqrhnl6Yg0vTuPEolTZdVZhLuV5HUd2doF
         hYSpGN39icTHThRpurltdyYxIH5VUxyfZIFS9dk1SaCynEOjbqMRCWOKFJ9Ctqxrsiiy
         gMnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N9w0ao85Eknm/KN+XsjJ7wUADghVqfHB84LDtTvPu94=;
        b=H4KfIXKsfadiXjAcQlNkLuX9Q9+3NmY29eroohihmBfuYImnn5nplyUtVqxWH1tbGK
         AZ7SO+sISLgo7JY2o5NCtMvDm1EZa5TRSpgnYQD4M3uKqzSewFmHxcAJSHWnJ4oexZc2
         mj0wQimrWsDdHEOvRq6tWWt8+SOEATRM/28+JWf469YQGuZMa5izPECDX/Cmg8plTFIE
         kuXiiYVKYgzbyxz2LtmWlLog8UKq2I05hsOyDs9lHh6RcTFc9x78IofGHOKDMwcUErv8
         dyQmZh1+q0Xy//1XxbHOdnt8GnrYXZArnmPO1+qifweoTClud7XYbl5OHZKK0OlnRCZZ
         Whbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N9w0ao85Eknm/KN+XsjJ7wUADghVqfHB84LDtTvPu94=;
        b=JyPW/vE2WcFGXgKbA2qYOy9GKbeEX/C947Yx3EfcJ2O3OUAk6aEqM8tT7Gj0Ce52nd
         zLdNOWV8N7LXMUa2ojksLT4XmQhzldORnTOyUJBiJyc0ADhEpj5h3kLQZEgp4XodxK3z
         KzYjJp4FbDDLHhWj9VwEbO1xGUr9T7wFtWW3gNXwGOrviwNE0sEkaiptXV3kErYMuINW
         rF8lD3/rY0ODJOhJXo4UU9FfhW6gYXNKr0toKZOtGApTWANTn1HMTOoREZTkdBqjAtmo
         XWGEepzAhStgxU9FZpsW5OQcE7aV/y5Fy6T2nMcL3HWLbYpUAWMmzp7/oSA9rKWpnEEE
         jbgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533C2Coc4fsFPpnNBoUn7HN15JsMxSIKw21nQ5xekDpXK165zgJV
	5M4vIJbmB9XKyVJL2BrlxaM=
X-Google-Smtp-Source: ABdhPJwkaTKrGWfzIa2kV8SvTp1tYOR6HtSFTl/xjI7BucLgmfmd7XXLlOgaCk/+L6nMvJHykw4wpA==
X-Received: by 2002:a17:90a:66ce:: with SMTP id z14mr29333540pjl.153.1608031693281;
        Tue, 15 Dec 2020 03:28:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b782:: with SMTP id e2ls9312859pls.10.gmail; Tue, 15
 Dec 2020 03:28:12 -0800 (PST)
X-Received: by 2002:a17:902:7596:b029:da:b7a3:cdd0 with SMTP id j22-20020a1709027596b02900dab7a3cdd0mr2153673pll.14.1608031692635;
        Tue, 15 Dec 2020 03:28:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608031692; cv=none;
        d=google.com; s=arc-20160816;
        b=NJNUPf9c+0k55nc2IL5DyB5oEDshTa1tz7Iyql1HxR5/12+4KmnpvoVo/uJvqcIt3a
         DnD9FIMPDQBxztv+lXNPMSwYOEx1WTXRrLVzEJqXm9Fd3VmX7MDqysLEdTKBNo8GWODb
         hbbEVV/nv45aBvDyK3mMtvMM8Cpvtg8bWwsDASjxpQR4D49EXGiBh/qtENHz+bukTCHj
         RRrEgzY7Z3sC8sKTft3Y7MrgvDtZFM+7wyfziWmUSuZm2xvS3CHsGFDXRdxP0HFh8yOS
         DyDZ/ZFLRVzTf8TXSyEVVJjxTFLGUzP1teXEOUARyW14NRk1pt0O6xw9u2ortyKIiq+R
         2V2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=yKeVSLRQA3b7WWkL80WouRwlRH34UmsKrjgZqaywmSI=;
        b=fsuJaxw0yY66JcLiV8Md0RmGOtJ0eZQZackh/H1YGBvXlPdEhuQ6pkpWfS1jZQjO5g
         0VgIp4R4IsPv54TKRg3PTyxLMFRLj3oE5+s6eBvrL8RWtEVgqL0XBs3v4kZneD1DgTXq
         qMLFvKA/mPHIFtDg3OexqDa6AHlOXkknpoLfz1BvXutb8TgiZdc366IQ0SadDwL3bO4t
         UhrpoTdgLNkcLQ/s3UbgQOUIsdEriLSo8xDY7rUaSdLCcA901MkI1ej++OMkcLoDegs1
         0+3kYN0zFFbNVk6GjHoTmOa3oPBtMs0J0/DbCu1AM+I+XNfiPQoiCnPCDN+bGbGiSpmq
         nQQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id w6si1402714pjr.2.2020.12.15.03.28.12
        for <kasan-dev@googlegroups.com>;
        Tue, 15 Dec 2020 03:28:12 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 74af20f4442d4610a8196286d9c1b5d3-20201215
X-UUID: 74af20f4442d4610a8196286d9c1b5d3-20201215
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1843917828; Tue, 15 Dec 2020 19:28:07 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs02n2.mediatek.inc (172.21.101.101) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 15 Dec 2020 19:28:05 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 15 Dec 2020 19:28:06 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<stable@vger.kernel.org>, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH 0/1] kasan: fix memory leak of kasan quarantine
Date: Tue, 15 Dec 2020 19:28:02 +0800
Message-ID: <1608031683-24967-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 1.9.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: CEAC96A1271FBFF82137D5C0B6036E94D5C347EC715C678B73A9F1D58F9F14102000:8
X-MTK: N
X-Original-Sender: kuan-ying.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

When cpu is going offline, set q->offline as true
and interrupt happened. The interrupt may call the
quarantine_put. But quarantine_put do not free the
the object. The object will cause memory leak.

Add qlink_free() to free the object.

Kuan-Ying Lee (1):
  kasan: fix memory leak of kasan quarantine

 mm/kasan/quarantine.c | 1 +
 1 file changed, 1 insertion(+)

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1608031683-24967-1-git-send-email-Kuan-Ying.Lee%40mediatek.com.
