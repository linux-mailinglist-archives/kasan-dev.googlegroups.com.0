Return-Path: <kasan-dev+bncBCM3H26GVIOBBK4B4SVQMGQEU53QYBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 655ED810709
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 01:54:05 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-590f402d0c1sf3601931eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 16:54:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702428844; cv=pass;
        d=google.com; s=arc-20160816;
        b=p2RG9wtkBIXDtvhwyQhIr2qcnKUCNkYeU6Qa9KT8ovP/xj7TiH1EWbDSY1xVf5Kd8C
         WxUSUbjnkQPiIDMDoAeworEf8OEENwf5Yz60IJZAv1kOF3WMX9V0KP6We0dS9sHQ7x6l
         rPuN2XD7hE6GpmJHxQvtmFUeE1LQiX5+n6ipq5lLkTHZbmI86RMJIZKd8OoEy/pkDHdV
         TEeZ8ZmS/85PbwlJ0vmlC/Ah5QDqiGnafCN+cCnHLyLI8NPvvjzpeybfWUtxUGpPgavT
         sIgwYalWVeo+CuijAUH7ZtmaioG/YqBSKQz/WNHNS0Mf3CLFmrv1ADxELvCdY4vdHUup
         hp8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=rH/NtQwds/FB0wByha1QLnzd7p2RL3nRMePFVsWPxok=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=MFKyOwiTCPBEWATHnIlt2KQqmAkLhG4Ospl6RKikdKlpVf9KYAFVrHvSAHROAJ218K
         Dp2CynqFeVwTVJ4BFg3DGlqclJzkxA+I59Bv6FMceLSIakq+ml90OCntF+euDy+41F09
         uaGtK/a40Ma1q+QhOz5SJrYjef1OTxVuojW0P2k0broonYHsxcnY5oBOknBhur5Pabv0
         0k/6O19MSHqkwaqzMW441VbvRVer7kMkvOYdhx+gpg6n6sCUXfP3LSdPf5D4cvr+iZD1
         HZ4R6HrjAUeI+F6vRO+guP7xzgfsz1nNa57nAvOlbKUTDg+mvkJsJupeAcCslBlcBoAV
         t14Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="ao/jdpu2";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702428844; x=1703033644; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rH/NtQwds/FB0wByha1QLnzd7p2RL3nRMePFVsWPxok=;
        b=wC6S/WbhMJd2bZnXi38giGLQew1WaNEKLtd1ssBlcWhV1P4o0N1Ubpso05DflCjpmS
         PQ5lTcA/0MgLut/evw4+kJ0++d4XlNRsIYO6AGVVBekJqObXia7FEqny0G0dFrGWYx1l
         +m5ex+6IbRxYVKFclkzA3iurXJGZL+aC5+5fB4VfFy54bcMRyknof+Mj59BWp79zLqgA
         8rQa2PdS7TP8vOG2GjjwOCEQgJuhrkSEQSfyXlg3qdRQk/kOexDXkPh/J8AQLvBdObmo
         0UyI1OXW8CGWdiMGgYmbTKlrfp1bYRv2B2L/I7gPpkvsSh293tcT1oJy9X6kmj7zjH0U
         +XLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702428844; x=1703033644;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rH/NtQwds/FB0wByha1QLnzd7p2RL3nRMePFVsWPxok=;
        b=Dv5AS1G+P+ySVTi0fUfQfmzxFmJSTBFRyQ5b4XEYxl1gImIjCcnNlcpcHHnbaeqRcC
         b3LJ7txxVnM/OzUV11MWin6usKn6Ly67CTLzl39mDAPszPZAEoKHsmBOE3nYX5Ed3bA1
         VYcUkTv0E3Gp0ulyUFFRfPfGLTMprsIQKhTVXK/kU1/rRHlfzpmv28WobgRVEEsByTqG
         Ik+KQrsQ6Z/RAHH4it9j3ufosqaygQbHnmkCTWycNoZwlTiFaIG4NDbj79BDff7Kpb1W
         hvnwnc9oTdEyrMVhH09D6Me59TuMaMKBCMRnIq4J5Vr5oJgs3pW3WPrMmBGKjYsg8drP
         139A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyPlPTdRI+57+2MZ6bknI+4J7WyEKxY4MuStdHqsDbONiSvUu7e
	KVLAqofysYjSGrSJ+ZGFMrc=
X-Google-Smtp-Source: AGHT+IFSCaVrbLYoLzuQ9QlNXG6+xbzyZuyIt0BaJiMR+HSWDXsu+EcEA8gcjHfX7EQf2hPo0p5dhQ==
X-Received: by 2002:a05:6820:2224:b0:58d:9942:b49 with SMTP id cj36-20020a056820222400b0058d99420b49mr6086078oob.9.1702428843872;
        Tue, 12 Dec 2023 16:54:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:2219:b0:58d:5625:1526 with SMTP id
 cj25-20020a056820221900b0058d56251526ls1284167oob.2.-pod-prod-03-us; Tue, 12
 Dec 2023 16:54:03 -0800 (PST)
X-Received: by 2002:a9d:6841:0:b0:6d9:f69a:392c with SMTP id c1-20020a9d6841000000b006d9f69a392cmr6264213oto.31.1702428843154;
        Tue, 12 Dec 2023 16:54:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702428843; cv=none;
        d=google.com; s=arc-20160816;
        b=0zMbF6miVlVeBLE5X+woQSRPBApKeXvXfdgMxbRZVxx1BbVyQgcVGjWMp1RFwxzz1Q
         xcMYaYA8fE6QFZjOk4vHsM36a11VEwyy3p07Sc0LYQUub6RWQ0E6Nyfj96cKuinglPQy
         RzuKivFFWgJCw8o3EKnjigVNsC2UClvYvEJvvOKxMmaksp64y10Kwv72l9YljfXFoaV9
         tRdrre05U/ptFYc1Ezzl9qt2o5GUaeOi/oatldakx8M7OJvdorrLvy2pd+5rBbk1ySks
         8Uj06PU7Q27gJcMfmsRitnzjyHd6twzAiySifZ7/BUvtGBUcv6V+tXh//LtQTnTRnasG
         tgxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=lbS2sOhFO9H2/jPqcY5CcYk1fjHyj8RVG0VTiN5eHDE=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=G12epe/qgB6SVTyicQuVB3jCYRKxzyRJaxj3TA+K94u5I4uinyqrWVyBTwpiOK5Ip1
         9s1fFAj7nounFBglTG0VAAf0VcuV0FyLP8HwHqxm9v0UdUS76JbEuwaVOrq2qdQhjLVI
         9/jMgpJ2VnqnVjibqtrTQRaH2j9a68unz7FYyLUiISeA8VrCLru8r3qwbFAB4CJnyj/o
         SipcTfc6XQwe5mRZtSxU4+naIOc1MQeAR60+/fbMtWBUboMSSPbQUn94+yKlFmK7VmdO
         U6SBnG5pmejEVMnLj/CDeexAUR2+9hAFgWuiUEBBJSEBn3qghlULedunPpH5y0gNx8q7
         8CTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="ao/jdpu2";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id l41-20020a056122202900b004b2f93695f7si1023324vkd.4.2023.12.12.16.54.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Dec 2023 16:54:03 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BCMv1DX002263;
	Wed, 13 Dec 2023 00:53:58 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uy0rv2k3s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 00:53:58 +0000
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BD0diKk022697;
	Wed, 13 Dec 2023 00:53:57 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uy0rv2k35-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 00:53:57 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BCN7OsC013874;
	Wed, 13 Dec 2023 00:53:56 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw5924m32-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 00:53:55 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BD0rr0214221950
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 00:53:53 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 307E92004B;
	Wed, 13 Dec 2023 00:53:53 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E28A720040;
	Wed, 13 Dec 2023 00:53:51 +0000 (GMT)
Received: from [9.171.70.156] (unknown [9.171.70.156])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 00:53:51 +0000 (GMT)
Message-ID: <679e7142d4ed4da34b6b4b756216170d6c789e84.camel@linux.ibm.com>
Subject: Re: [PATCH v2 18/33] lib/string: Add KMSAN support to strlcpy() and
 strlcat()
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
        Andrew Morton
 <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>,
        David
 Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
        Joonsoo
 Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami
 Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven
 Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil
 Babka <vbabka@suse.cz>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle
 <svens@linux.ibm.com>
Date: Wed, 13 Dec 2023 01:53:51 +0100
In-Reply-To: <CAG_fn=XQkhecLYFmJugOG+GawvDQ5Xsj5fTRbOAhU8Z5CfsjPA@mail.gmail.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
	 <20231121220155.1217090-19-iii@linux.ibm.com>
	 <CAG_fn=XQkhecLYFmJugOG+GawvDQ5Xsj5fTRbOAhU8Z5CfsjPA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: CoFzpVB1hjayWnb5EoMT-xEl3omYP96D
X-Proofpoint-ORIG-GUID: hDPpadErq5XkPzsxCdCzkDyCXRSYxuts
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-12_14,2023-12-12_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 suspectscore=0 spamscore=0 lowpriorityscore=0 mlxlogscore=812
 malwarescore=0 priorityscore=1501 phishscore=0 bulkscore=0 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130004
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="ao/jdpu2";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

On Fri, 2023-12-08 at 17:50 +0100, Alexander Potapenko wrote:
> On Tue, Nov 21, 2023 at 11:02=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.=
com>
> wrote:
> >=20
> > Currently KMSAN does not fully propagate metadata in strlcpy() and
> > strlcat(), because they are built with -ffreestanding and call
> > memcpy(). In this combination memcpy() calls are not instrumented.
>=20
> Is this something specific to s390?

Nice catch - I can't reproduce this behavior anymore. Even if I go
back to the clang version that first introduced KMSAN on s390x, the
memset() instrumentation with -ffreestanding is still there. I should
have written down more detailed notes after investigating this, but
here we are. I will drop this patch as well as 10/33.

[...]

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/679e7142d4ed4da34b6b4b756216170d6c789e84.camel%40linux.ibm.com.
