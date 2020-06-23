Return-Path: <kasan-dev+bncBCPKJIPIMYIJ3LOK64CRUBCWIDOMO@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 1834A2068B8
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 01:56:14 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id v78sf356868oif.8
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 16:56:14 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UYI/JrZeOoB7jYilCM1zR9hH8OL4wMuTGd3rPeCYqXM=;
        b=NxS3QCSWvP15rIZSmIhH7ZzLdM/mOx+qc8aUo3V7tNAMYMyHCOl01Y5AgPgCAD44z0
         lXQJSiFxj8Syv2nT6YhDoc7f/0YylzJckRwldGFaU2bs8pQShvsz27t41QOBGUI8Fqd7
         qxe7UJvuvuUcMCTYL2evBtT3oJhsK/wQCPMp5FUTkZ+0qMi5NBmPptiHO8WV98G+GXhR
         zTAS0azQtXWG3nRdHbGIv3YBkYN8OKLIIdVkmDJ1Qxlv1Hf4GrfVsDYIJIlhQd0d92W5
         4eQ5LDaalsOpAKVJYuOo6t71+FCzckTGpwuYHLr28iVEcOqdBpA0ZlHO9i6uFD+40rkA
         fWNQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UYI/JrZeOoB7jYilCM1zR9hH8OL4wMuTGd3rPeCYqXM=;
        b=aPB70L2sV4KPxPExQ7nhXgr+BZ40CA0IYDaKDlG3XyhzlLcIRtdSu0RXPGfEWEQDod
         5IbN3Nmy0+FDM71WEAFUvofBuRDebt2y2KoVL6l3h0LOo05mgt6vVYRrrs3nbOukgUGx
         0YtVx7Bw+o+yvfzMeUdKG/lYd6LzwZ5Q9cjVCPmBfjL9uybLaIj06zRtM9CxU7L7D+9J
         vBCLUAfEe3HNucEhjZ/1yj4S7w3pNpkQV8SxrevAhCgGNaTx8DZU9UJgBbiHLAKUa7Js
         uce00v077HiX4T1aBLhcZxuaMcqR1jHiKltsOW/clEG/k10YGVU3UTk95RPUI5fIHMPA
         1z9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UYI/JrZeOoB7jYilCM1zR9hH8OL4wMuTGd3rPeCYqXM=;
        b=UfgEfx1/i1pM2R012CyuIil50mkrIOuh7QlRnQwK+vI8Z+qQOhIQkZRDIiLkukwiy0
         ftoBhyer02sfyGdE13INVgERSNn0MDeyQj+XM3p8wWalOUy5huQOamYtN0PwX28X5s7M
         FdhVF8CqrKUPBdTmqCU9pWDTzFu02N4JDqvf23Sneu+/sPzSUd+87WficvQKJgdn87sN
         v1NsH5UQE1Wm/mPGJPhZc8piU0fFImxaRz1LB5V7r2G0aYrQMmAFGkzilemoB0f5Hini
         44tYcwqStYTdVUfYgMzHeaY7B0/YlFMuEFwywvdjpd3sldPKoVU3s6/h1fvPFpmGDsgl
         3ehg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531J/Nc5wLvCsqEcUe78gYpKUnCXOAVYiz5ATcOc2g40pENzMebe
	SYfzqcKN3ZIOCh7xD0n761o=
X-Google-Smtp-Source: ABdhPJzxOHc3aDk0arovUGL0JYwEyFFrABur/fQ07u8VIbIMTbNlwVKLyC8t/dTfn/F24cP7PQILPw==
X-Received: by 2002:a9d:39f4:: with SMTP id y107mr21130876otb.191.1592956573095;
        Tue, 23 Jun 2020 16:56:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d24f:: with SMTP id e15ls32237oos.1.gmail; Tue, 23 Jun
 2020 16:56:12 -0700 (PDT)
X-Received: by 2002:a4a:4c8e:: with SMTP id a136mr20852031oob.23.1592956572695;
        Tue, 23 Jun 2020 16:56:12 -0700 (PDT)
Date: Tue, 23 Jun 2020 16:56:11 -0700 (PDT)
From: iceman.jere@gmail.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <e8bd3ded-1e66-474a-84a8-fa0523633cado@googlegroups.com>
In-Reply-To: <782527173.1143749.1592797208205@mail.yahoo.com>
References: <1408139245.1302051.1591161262589.ref@mail.yahoo.com> <1408139245.1302051.1591161262589@mail.yahoo.com> <368102206.1302961.1591161296756@mail.yahoo.com> <662368049.94387.1591161344870@mail.yahoo.com> <1705927180.1154180.1592797171602@mail.yahoo.com>
 <782527173.1143749.1592797208205@mail.yahoo.com>
Subject: Re: Hello
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_5491_533888586.1592956572009"
X-Original-Sender: Iceman.Jere@gmail.com
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

------=_Part_5491_533888586.1592956572009
Content-Type: text/plain; charset="UTF-8"

Hi there, I'm Jere, what's up baby?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e8bd3ded-1e66-474a-84a8-fa0523633cado%40googlegroups.com.

------=_Part_5491_533888586.1592956572009--
